#! /usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import logging
import os
import subprocess
import sys
import tempfile
import traceback
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from urllib.parse import urlparse


def virsh(connection, *args):
    cmd = ("virsh", "-c", f"qemu:///{connection}", *args)
    logging.debug("Running virsh command: %s", ' '.join(cmd))
    return subprocess.check_output(cmd)


def assert_vm_exists(connection, name):
    # This function should never raise Exception
    try:
        subprocess.check_call(["virsh", "-c", f"qemu:///{connection}", "domuuid", name])
    except subprocess.CalledProcessError:
        logging.error("VM disappeared while being created")
        raise


def get_graphics_capabilies(connection):
    capabilities = virsh(connection, 'domcapabilities')

    root = ET.ElementTree(ET.fromstring(capabilities))
    graphics = root.find('devices').find('graphics')
    supported = graphics.get('supported')

    consoles = []
    if supported == 'yes':
        for value in graphics.find('enum').findall('value'):
            consoles.append(value.text)

    logging.debug('get_graphics_capabilies: %s', ', '.join(consoles))
    return consoles


def prepare_graphics_params(connection):
    graphics_cap = get_graphics_capabilies(connection)
    params = []
    if 'vnc' in graphics_cap:
        params += ['--graphics', 'vnc']
    else:
        params += ['--graphics', 'none']
    return params


@contextmanager
def prepare_unattended(args):
    params = []
    if args['type'] == 'create' and args['unattended']:
        params.append("--unattended")

        unattended_params = [f"profile={args['profile']}"]

        if args['rootPassword']:
            root_pass_file = tempfile.NamedTemporaryFile(
                prefix="cockpit-machines-",
                suffix="-admin-password",
                mode='w+'
            )
            root_pass_file.write(args['rootPassword'])
            root_pass_file.flush()
            unattended_params.append(f"admin-password-file={root_pass_file.name}")

        if args['userLogin']:
            unattended_params.append(f"user-login={args['userLogin']}")

        if args['userPassword']:
            user_pass_file = tempfile.NamedTemporaryFile(
                prefix="cockpit-machines-",
                suffix="-user-password",
                mode='w+'
            )
            user_pass_file.write(args['userPassword'])
            user_pass_file.flush()
            unattended_params.append(f"user-password-file={user_pass_file.name}")

        params.append(",".join(unattended_params))

    yield params


@contextmanager
def prepare_cloud_init(args):
    params = []
    if args['sourceType'] == 'cloud' and (args['type'] == 'install' or args['startVm']):
        user_data_file = tempfile.NamedTemporaryFile(
            prefix="cockpit-machines-",
            suffix="-user-data",
            mode='w+'
        )
        user_data_file.write("#cloud-config\n")
        if args.get('hostname'):
            user_data_file.write(f"hostname: {args['hostname']}\n")
            user_data_file.write("manage_etc_hosts: true\n")
        if args['userLogin']:
            user_data_file.write("users:\n")
            user_data_file.write(f"  - name: {args['userLogin']}\n")
            user_data_file.write("    sudo: ALL=(ALL) NOPASSWD:ALL\n")
            user_data_file.write("    shell: /bin/bash\n")
            user_data_file.write("    lock_passwd: false\n")
            if 'sshKeys' in args and len(args['sshKeys']) > 0:
                user_data_file.write("    ssh_authorized_keys:\n")
                for key in args['sshKeys']:
                    user_data_file.write(f"      - {key}\n")

        if args['rootPassword'] or args['userPassword']:
            # enable SSH password login if any password is set
            user_data_file.write("ssh_pwauth: true\n")
            user_data_file.write("chpasswd:\n")
            user_data_file.write("  list: |\n")
            if args['rootPassword']:
                user_data_file.write(f"    root:{args['rootPassword']}\n")
            if args['userPassword']:
                user_data_file.write(f"    {args['userLogin']}:{args['userPassword']}\n")
            user_data_file.write("  expire: False\n")

        user_data_file.flush()

        # Cloud-init's NoCloud datasource requires both user-data AND meta-data
        # files in the cidata volume. virt-install's built-in metadata generator
        # returns an empty string, which makes _CloudInitConfig.add_filepair()
        # skip the meta-data file entirely. The resulting cidata.iso has only
        # user-data, and cloud-init then fails to apply any of it. Generate a
        # minimal meta-data with a stable instance-id (the VM name) and pass it
        # explicitly so the iso ends up complete.
        meta_data_file = tempfile.NamedTemporaryFile(
            prefix="cockpit-machines-",
            suffix="-meta-data",
            mode='w+'
        )
        meta_data_file.write(f"instance-id: {args['vmName']}\n")
        if args.get('hostname'):
            meta_data_file.write(f"local-hostname: {args['hostname']}\n")
        meta_data_file.flush()

        # Force a MAC-based DHCP client identifier. Cloud images (Ubuntu et al.)
        # default systemd-networkd to dhcp-identifier=duid, which sends an
        # RFC 4361 client-id distinct from the MAC-based id used by the
        # initramfs/early-boot DHCP request. A MAC-keyed DHCP server (dnsmasq)
        # then issues TWO leases for one NIC - one per identifier - so the
        # guest's address flips mid-boot and looks like it "loses" its IP.
        # Pinning dhcp-identifier=mac makes every request use the same id, so
        # the guest holds a single stable lease. Match e* to cover eth0 and
        # predictable en* names across images.
        network_config_file = tempfile.NamedTemporaryFile(
            prefix="cockpit-machines-",
            suffix="-network-config",
            mode='w+'
        )
        network_config_file.write("version: 2\n")
        network_config_file.write("ethernets:\n")
        network_config_file.write("  cockpit-default:\n")
        network_config_file.write("    match:\n")
        network_config_file.write("      name: \"e*\"\n")
        network_config_file.write("    dhcp4: true\n")
        network_config_file.write("    dhcp-identifier: mac\n")
        network_config_file.flush()

        # virt-install expects all --cloud-init sub-options in a single
        # comma-separated argument: --cloud-init user-data=X,meta-data=Y
        params.append("--cloud-init")
        params.append(
            f"user-data={user_data_file.name},meta-data={meta_data_file.name},"
            f"network-config={network_config_file.name}"
        )

    yield params


def prepare_installation_source(args):
    params = []
    only_define = args['type'] == 'create' and not args['startVm']
    if only_define:
        params.append("--print-xml=1")
        return params

    if args['sourceType'] == "pxe":
        params += ['--pxe', '--network', args['source']]
    elif args['sourceType'] == "os":
        params += ['--install', f"os={args['os']}"]
        if args['extraArguments']:
            params += ['--extra-args', args['extraArguments']]
    elif args['sourceType'] in ['disk_image', 'cloud']:
        params.append("--import")
    elif ((args['source'][0] == '/' and os.path.isfile(args['source'])) or
            (args['sourceType'] == 'url' and urlparse(args['source']).path.endswith(".iso"))):
        params += ['--cdrom', args['source']]
    else:
        params += ['--location', args['source']]
        if args['extraArguments']:
            params += ['--extra-args', args['extraArguments']]

    return params


@contextmanager
def prepare_virt_install_params(args):
    logging.debug(args)
    with prepare_unattended(args) as unattended_params, prepare_cloud_init(args) as cloud_init_params:
        params = [
            "virt-install",
            "--connect", f"qemu:///{args['connectionName']}",
            "--quiet",
            "--os-variant", args['os']
        ]

        if args['type'] == 'install':
            params += ['--reinstall', args['vmName']]
        else:
            params += [
                "--memory", str(args['memorySize']),
                "--name", args['vmName']
            ]

        if 'storagePool' in args and args['storagePool'] not in ['NewVolumeQCOW2', 'NewVolumeRAW']:
            params += ["--check", "path_in_use=off"]

        if args['sourceType'] != 'disk_image':
            params += ["--wait", "-1"]

        if args['type'] == 'install' or args['startVm']:
            params.append("--noautoconsole")

        # Disks
        if args['type'] != 'install':
            params.append("--disk")

            if args['sourceType'] == 'disk_image':
                disk = f"{args['source']},device=disk"
            elif args['storagePool'] == 'NoStorage':
                disk = "none"
            else:
                if args['storagePool'] not in ['NewVolumeQCOW2', 'NewVolumeRAW']:
                    disk = f"vol={args['storagePool']}/{args['storageVolume']}"
                else:
                    disk = f"size={args['storageSize']}"
                    if args['storagePool'] == 'NewVolumeQCOW2':
                        disk += ",format=qcow2"
                    elif args['storagePool'] == 'NewVolumeRAW':
                        disk += ",format=raw"
                if args['sourceType'] == "cloud":
                    disk += f",backing_store={args['source']}"
            params.append(disk)

        # Consoles
        if args['type'] != "install":
            params += prepare_graphics_params(args['connectionName'])

        # Installation media
        params += prepare_installation_source(args)

        # VCPUs
        if 'vcpu' in args:
            params += ['--vcpus', args['vcpu']]

        # Firmware
        if 'firmware' in args:
            params += ['--boot', args['firmware']]

        params += unattended_params
        params += cloud_init_params

        logging.debug(params)

        yield params


def create_vm(args):
    with prepare_virt_install_params(args) as params:
        xml = subprocess.check_output(params)

    if args['startVm']:
        try:
            assert_vm_exists(args['connectionName'], args['vmName'])

            xml = virsh(args['connectionName'], "dumpxml", "--inactive", args['vmName'])
        except subprocess.CalledProcessError:
            logging.info("The VM got deleted while being installed")
            logging.info(traceback.format_exc())
            sys.exit(0)

    xml_last_phase = xml.strip().split(b'\n\n')[-1]
    # Get last step only - virt-install can output 1 or 2 steps
    inject_metadata(xml_last_phase.decode())


def install_vm(args):
    prevXML = virsh(args['connectionName'], "dumpxml", args['vmName'])

    with prepare_virt_install_params(args) as params:
        try:
            subprocess.check_output(params)
        except subprocess.CalledProcessError as e:
            logging.exception(e)
            # If virt-install returned non-zero return code, redefine
            # the VM so that we get back the metadata which enable the 'Install'
            # button, so that the user can re-attempt installation
            with tempfile.NamedTemporaryFile() as file:
                logging.debug("virt-install failed, redefining to re-enable the 'Install' button")
                file.write(prevXML)
                file.flush()
                virsh(args['connectionName'], "define", file.name)
            raise e

        assert_vm_exists(args['connectionName'], args['vmName'])

        xml = virsh(args['connectionName'], "dumpxml", "--inactive", args['vmName'])

        inject_metadata(xml.decode())


def inject_metadata(xml):
    # Register used namespaces
    ns = {"cockpit_machines": "https://github.com/cockpit-project/cockpit-machines"}
    ET.register_namespace("cockpit_machines", ns["cockpit_machines"])
    ET.register_namespace("libosinfo", "http://libosinfo.org/xmlns/libvirt/domain/1.0")

    # ET.fromstring() already wants UTF-8 encoded bytes
    root = ET.fromstring(xml)
    metadata = root.find('metadata')
    cockpit_machines_metadata = metadata.find('cockpit_machines:data', ns)
    if cockpit_machines_metadata:
        metadata.remove(cockpit_machines_metadata)

    has_install_phase = "true"
    # VM does not have a pending install phase (visible Install button in the UI) if:
    # - The script is called from the 'Install' button
    # - The script is called from the 'Create' dialog and the VM is started (installer will run)
    # - The script is called from the 'Import' dialog
    if args['type'] == 'install' or args['startVm'] or args['sourceType'] == 'disk_image':
        has_install_phase = "false"

    METADATA = f'''
<cockpit_machines:data xmlns:cockpit_machines="https://github.com/cockpit-project/cockpit-machines"> \
  <cockpit_machines:has_install_phase>{has_install_phase}</cockpit_machines:has_install_phase> \
  <cockpit_machines:install_source_type>{args['sourceType']}</cockpit_machines:install_source_type> \
  <cockpit_machines:install_source>{args['source']}</cockpit_machines:install_source> \
  <cockpit_machines:os_variant>{args['os']}</cockpit_machines:os_variant> \
'''
    if has_install_phase == "true" and args['sourceType'] == 'cloud':
        if args['rootPassword']:
            METADATA += f"<cockpit_machines:root_password>{args['rootPassword']}</cockpit_machines:root_password>"
        if args['userLogin']:
            METADATA += f"<cockpit_machines:user_login>{args['userLogin']}</cockpit_machines:user_login>"
        if args['userPassword']:
            METADATA += f"<cockpit_machines:user_password>{args['userPassword']}</cockpit_machines:user_password>"
        if args.get('hostname'):
            METADATA += f"<cockpit_machines:hostname>{args['hostname']}</cockpit_machines:hostname>"
        # Stash the SSH keys list as a single newline-joined blob so the
        # 'Install' button on a pending-install VM can carry the keys
        # through. Without this, domainInstall reads the metadata back, finds
        # no sshKeys field, and rebuilds the user-data with userLogin only -
        # the user lands without any way to log in.
        if 'sshKeys' in args and len(args['sshKeys']) > 0:
            from xml.sax.saxutils import escape as _xml_escape
            ssh_keys_blob = "\n".join(args['sshKeys'])
            METADATA += f"<cockpit_machines:ssh_keys>{_xml_escape(ssh_keys_blob)}</cockpit_machines:ssh_keys>"

    if args['extraArguments']:
        METADATA += f"<cockpit_machines:extra_arguments>{args['extraArguments']}</cockpit_machines:extra_arguments>"

    METADATA += "</cockpit_machines:data>"

    cockpit_machines_metadata_new = ET.fromstring(METADATA)
    metadata.append(cockpit_machines_metadata_new)

    updated_xml = ET.tostring(root)

    with tempfile.NamedTemporaryFile() as file:
        file.write(updated_xml)
        file.flush()
        virsh(args['connectionName'], "define", file.name)


logging.basicConfig(level=logging.ERROR, format='%(message)s')
logging.debug(sys.argv[1])

args = json.loads(sys.argv[1], strict=False)

logging.debug(args)

if args['type'] == 'create':
    create_vm(args)
elif args['type'] == 'install':
    install_vm(args)
else:
    raise NotImplementedError("unknown type " + args['type'])
