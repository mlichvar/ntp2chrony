#!/usr/bin/python
#
# Convert ntp configuration to chrony
#
# Copyright (C) 2018  Miroslav Lichvar <mlichvar@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import ipaddress
import os
import os.path
import re
import subprocess
import sys

# python2 compatibility hacks
if sys.version_info[0] < 3:
    from io import open
    reload(sys)
    sys.setdefaultencoding("utf-8")

class NtpConfiguration(object):
    def __init__(self, root_dir, ntp_conf, step_tickers, verbose):
        self.root_dir = root_dir if root_dir != "/" else ""
        self.ntp_conf_path = ntp_conf
        self.step_tickers_path = step_tickers
        self.verbose = verbose

        self.enabled_services = set()
        self.step_tickers = []
        self.time_sources = []
        self.fudges = {}
        self.restrictions = {
                # Built-in defaults
                ipaddress.ip_network(u"0.0.0.0/0"): set(),
                ipaddress.ip_network(u"::/0"): set(),
        }
        self.keyfile = ""
        self.keys = []
        self.trusted_keys = []
        self.driftfile = ""
        self.statistics = []
        self.leapfile = ""
        self.tos_options = []
        self.ignored_directives = set()
        self.ignored_lines = []

        #self.detect_enabled_services()
        self.parse_step_tickers()
        self.parse_ntp_conf()

    def detect_enabled_services(self):
        for service in ["ntpdate", "ntpd", "ntp-wait"]:
            if os.path.islink("{}/etc/systemd/system/multi-user.target.wants/{}.service"
                    .format(self.root_dir, service)):
                self.enabled_services.add(service)
        if self.verbose > 0:
            print("Enabled services found in /etc/systemd/system: " +
                    " ".join(self.enabled_services))

    def parse_step_tickers(self):
        if not self.step_tickers_path:
            return

        path = self.root_dir + self.step_tickers_path
        if not os.path.isfile(path):
            if self.verbose > 0:
                print("Missing " + path)
            return

        with open(path, encoding="latin-1") as f:
            for line in f:
                line = line[:line.find('#')]

                words = line.split()

                if not words:
                    continue

                self.step_tickers.extend(words)

    def parse_ntp_conf(self, path=None):
        if path is None:
            path = self.root_dir + self.ntp_conf_path

        with open(path, encoding="latin-1") as f:
            if self.verbose > 0:
                print("Reading " + path)

            for line in f:
                line = line[:line.find('#')]

                words = line.split()

                if not words:
                    continue

                if not self.parse_directive(words):
                    self.ignored_lines.append(line)

    def parse_directive(self, words):
        name = words.pop(0)
        if name.startswith("logconfig"):
            name = "logconfig"

        if words:
            if name in ["server", "peer", "pool"]:
                return self.parse_source(name, words)
            elif name == "fudge":
                return self.parse_fudge(words)
            elif name == "restrict":
                return self.parse_restrict(words)
            elif name == "tos":
                return self.parse_tos(words)
            elif name == "includefile":
                return self.parse_includefile(words)
            elif name == "keys":
                return self.parse_keys(words)
            elif name == "trustedkey":
                return self.parse_trustedkey(words)
            elif name == "driftfile":
                self.driftfile = words[0]
            elif name == "statistics":
                self.statistics = words
            elif name == "leapfile":
                self.leapfile = words[0]
            else:
                self.ignored_directives.add(name)
                return False
        else:
            self.ignored_directives.add(name)
            return False

        return True

    def parse_source(self, type, words):
        ipv4_only = False
        ipv6_only = False
        source = {
                "type": type,
                "options": []
        }

        if words[0] == "-4":
            ipv4_only = True
            words.pop(0)
        elif words[0] == "-6":
            ipv6_only = True
            words.pop(0)

        if not words:
            return False

        source["address"] = words.pop(0)

        # Check if -4/-6 corresponds to the address and ignore hostnames
        if ipv4_only or ipv6_only:
            try:
                version = ipaddress.ip_address(source["address"]).version
                if (ipv4_only and version != 4) or (ipv6_only and version != 6):
                    return False
            except ValueError:
                return False

        if source["address"].startswith("127.127."):
            if not source["address"].startswith("127.127.1."):
                # Ignore non-LOCAL refclocks
                return False

        while words:
            if len(words) >= 2 and words[0] in ["minpoll", "maxpoll", "version", "key"]:
                source["options"].append((words[0], words[1]))
                words = words[2:]
            elif words[0] in ["burst", "iburst", "noselect", "prefer", "true", "xleave"]:
                source["options"].append((words[0],))
                words.pop(0)
            else:
                return False

        self.time_sources.append(source)
        return True

    def parse_fudge(self, words):
        address = words.pop(0)
        options = {}

        while words:
            if len(words) >= 2:
                options[words[0]] = words[1]
                words = words[2:]
            else:
                return False

        self.fudges[address] = options
        return True

    def parse_restrict(self, words):
        ipv4_only = False
        ipv6_only = False
        flags = set()
        mask = ""

        if words[0] == "-4":
            ipv4_only = True
            words.pop(0)
        elif words[0] == "-6":
            ipv6_only = True
            words.pop(0)

        if not words:
            return False

        address = words.pop(0)

        while words:
            if len(words) >= 2 and words[0] == "mask":
                mask = words[1]
                words = words[2:]
            else:
                if words[0] not in ["kod", "nomodify", "notrap", "nopeer", "noquery",
                                    "limited", "ignore", "noserve"]:
                    return False
                flags.add(words[0])
                words.pop(0)

        # Convert to IP network(s), ignoring restrictions with hostnames
        networks = []
        if address == "default" and not mask:
            if not ipv6_only:
                networks.append(ipaddress.ip_network(u"0.0.0.0/0"))
            if not ipv4_only:
                networks.append(ipaddress.ip_network(u"::/0"))
        else:
            try:
                if mask:
                    networks.append(ipaddress.ip_network(u"{}/{}".format(address, mask)))
                else:
                    networks.append(ipaddress.ip_network(address))
            except ValueError:
                return False

            if (ipv4_only and networks[-1].version != 4) or \
                    (ipv6_only and networks[-1].version != 6):
                return False

        for network in networks:
            self.restrictions[network] = flags

        return True

    def parse_tos(self, words):
        options = []
        while words:
            if len(words) >= 2 and words[0] in ["minsane", "maxdist", "orphan"]:
                options.append((words[0], words[1]))
                words = words[2:]
            else:
                return False

        self.tos_options.extend(options)

        return True

    def parse_includefile(self, words):
        path = self.root_dir + words[0]
        if not os.path.isfile(path):
            return False

        self.parse_ntp_conf(path)
        return True

    def parse_keys(self, words):
        keyfile = words[0]
        path = self.root_dir + keyfile
        if not os.path.isfile(path):
            if self.verbose > 0:
                print("Missing file " + path)
            return False

        with open(path, encoding="latin-1") as f:
            if self.verbose > 0:
                print("Reading " + path)
            keys = []
            for line in f:
                words = line.split()
                if len(words) < 3 or not words[0].isdigit():
                    continue
                keys.append((int(words[0]), words[1], words[2]))

            self.keyfile = keyfile
            self.keys = keys

        return True

    def parse_trustedkey(self, words):
        key_ranges = []
        for word in words:
            if word.isdigit():
                key_ranges.append((int(word), int(word)))
            elif re.match("^[0-9]+-[0-9]+$", word):
                first, last = word.split("-")
                key_ranges.append((int(first), int(last)))
            else:
                return False

        self.trusted_keys = key_ranges
        return True

    def write_chrony_configuration(self, chrony_conf_path, chrony_keys_path,
                                   dry_run=False, backup=False):
        chrony_conf = self.get_chrony_conf()
        if self.verbose > 1:
            print("Generated {}:\n{}".format(chrony_conf_path, chrony_conf))

        if not dry_run:
            self.write_file(chrony_conf_path, 0o644, chrony_conf, backup)

        chrony_keys = self.get_chrony_keys()
        if chrony_keys:
            if self.verbose > 1:
                print("Generated {}:\n{}".format(chrony_keys_path, chrony_keys))

        if not dry_run:
            self.write_file(chrony_keys_path, 0o640, chrony_keys, backup)

    def get_chrony_conf_sources(self):
        conf = ""

        if self.step_tickers:
            conf += "# Specify NTP servers used for initial correction.\n"
            conf += "initstepslew 0.1 {}\n".format(" ".join(self.step_tickers))
            conf += "\n"

        conf += "# Specify time sources.\n"

        for source in self.time_sources:
            address = source["address"]
            if address.startswith("127.127."):
                if address.startswith("127.127.1."):
                    continue
                assert False
            else:
                conf += "{} {}".format(source["type"], address)
                for option in source["options"]:
                    if option[0] in ["minpoll", "maxpoll", "version", "key",
                                     "iburst", "noselect", "prefer", "xleave"]:
                        conf += " {}".format(" ".join(option))
                    elif option[0] == "burst":
                        conf += " presend 6"
                    elif option[0] == "true":
                        conf += " trust"
                    else:
                        assert False
                conf += "\n"
        conf += "\n"

        return conf

    def get_chrony_conf_allows(self):
        allowed_networks = filter(lambda n: "ignore" not in self.restrictions[n] and
                                    "noserve" not in self.restrictions[n],
                                  self.restrictions.keys())

        conf = ""
        for network in sorted(allowed_networks, key=lambda n: (n.version, n)):
            if network.num_addresses > 1:
                conf += "allow {}\n".format(network)
            else:
                conf += "allow {}\n".format(network.network_address)

        if conf:
            conf = "# Allow NTP client access.\n" + conf
            conf += "\n"

        return conf

    def get_chrony_conf_cmdallows(self):
        allowed_networks = filter(lambda n: "ignore" not in self.restrictions[n] and
                                    "noquery" not in self.restrictions[n] and
                                    n != ipaddress.ip_network(u"127.0.0.1/32") and
                                    n != ipaddress.ip_network(u"::1/128"),
                                  self.restrictions.keys())

        ip_versions = set()
        conf = ""
        for network in sorted(allowed_networks, key=lambda n: (n.version, n)):
            ip_versions.add(network.version)
            if network.num_addresses > 1:
                conf += "cmdallow {}\n".format(network)
            else:
                conf += "cmdallow {}\n".format(network.network_address)

        if conf:
            conf = "# Allow remote monitoring.\n" + conf
            if 4 in ip_versions:
                conf += "bindcmdaddress 0.0.0.0\n"
            if 6 in ip_versions:
                conf += "bindcmdaddress ::\n"
            conf += "\n"

        return conf

    def get_chrony_conf(self):
        local_stratum = 0
        maxdistance = 0.0
        minsources = 1
        orphan_stratum = 0
        logs = []

        for source in self.time_sources:
            address = source["address"]
            if address.startswith("127.127.1."):
                if address in self.fudges and "stratum" in self.fudges[address]:
                    local_stratum = int(self.fudges[address]["stratum"])
                else:
                    local_stratum = 5

        for tos in self.tos_options:
            if tos[0] == "maxdist":
                maxdistance = float(tos[1])
            elif tos[0] == "minsane":
                minsources = int(tos[1])
            elif tos[0] == "orphan":
                orphan_stratum = int(tos[1])
            else:
                assert False

        if "clockstats" in self.statistics:
            logs.append("refclocks");
        if "loopstats" in self.statistics:
            logs.append("tracking")
        if "peerstats" in self.statistics:
            logs.append("statistics");
        if "rawstats" in self.statistics:
            logs.append("measurements")

        conf = "# This file was converted from {}{}.\n".format(
                    self.ntp_conf_path,
                    " and " + self.step_tickers_path if self.step_tickers_path else "")
        conf += "\n"

        if self.ignored_lines:
            conf += "# The following directives were ignored in the conversion:\n"

            for line in self.ignored_lines:
                # Remove sensitive information
                line = re.sub(r"\s+pw\s+\S+", " pw XXX", line.rstrip())
                conf += "# " + line + "\n"
            conf += "\n"

        conf += self.get_chrony_conf_sources()

        conf += "# Record the rate at which the system clock gains/losses time.\n"
        if not self.driftfile:
            conf += "#"
        conf += "driftfile /var/lib/chrony/drift\n"
        conf += "\n"

        conf += "# Allow the system clock to be stepped in the first three updates\n"
        conf += "# if its offset is larger than 1 second.\n"
        conf += "makestep 1.0 3\n"
        conf += "\n"

        conf += "# Enable kernel synchronization of the real-time clock (RTC).\n"
        conf += "rtcsync\n"
        conf += "\n"

        if maxdistance > 0.0:
            conf += "# Specify the maximum distance of sources to be selectable.\n"
            conf += "maxdistance {}\n".format(maxdistance)
            conf += "\n"

        conf += "# Increase the minimum number of selectable sources required to adjust\n"
        conf += "# the system clock.\n"
        if minsources > 1:
            conf += "minsources {}\n".format(minsources)
        else:
            conf += "#minsources 2\n"
        conf += "\n"

        conf += self.get_chrony_conf_allows()

        conf += self.get_chrony_conf_cmdallows()

        conf += "# Serve time even if not synchronized to a time source.\n"
        if orphan_stratum > 0 and orphan_stratum < 16:
            conf += "local stratum {} orphan\n".format(orphan_stratum)
        elif local_stratum > 0 and local_stratum < 16:
            conf += "local stratum {}\n".format(local_stratum)
        else:
            conf += "#local stratum 10\n"
        conf += "\n"

        conf += "# Specify file containing keys for NTP authentication.\n"
        conf += ("#" if not self.keys else "") + "keyfile /etc/chrony.keys\n"
        conf += "\n"

        conf += "# Get TAI-UTC offset and leap seconds from the system tz database.\n"
        conf += "leapsectz right/UTC\n"
        conf += "\n"

        conf += "# Specify directory for log files.\n"
        conf += "logdir /var/log/chrony\n"
        conf += "\n"

        conf += "# Select which information is logged.\n"
        if logs:
            conf += "log {}\n".format(" ".join(logs))
        else:
            conf += "#log measurements statistics tracking\n"
        conf += "\n"

        return conf

    def get_chrony_keys(self):
        if not self.keys:
            return ""

        keys = "# This file was converted from {}.\n".format(self.keyfile)
        keys += "\n"

        for key in self.keys:
            id = key[0]
            type = key[1]
            password = key[2]

            if type in ["m", "M"]:
                type = "MD5"
            elif type not in ["MD5", "SHA1", "SHA256", "SHA384", "SHA512"]:
                continue

            prefix = "ASCII" if len(password) <= 20 else "HEX"

            for first, last in self.trusted_keys:
                if first <= id <= last:
                    trusted = True
                    break
            else:
                trusted = False

            # Disable keys that were not marked as trusted
            if not trusted:
                keys += "#"

            keys += "{} {} {}:{}\n".format(id, type, prefix, password)

        return keys

    def write_file(self, path, mode, content, backup):
        path = self.root_dir + path
        if backup and os.path.isfile(path):
            os.rename(path, path + ".old")

        with open(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, mode), "w",
                  encoding="latin-1") as f:
            if self.verbose > 0:
                print("Writing " + path)
            f.write(u"" + content)

        # Fix SELinux context if restorecon is installed
        try:
            subprocess.call(["restorecon", path])
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Convert ntp configuration to chrony.")
    parser.add_argument("-r", "--root", dest="roots", default=["/"], nargs="+",
                        metavar="DIR", help="specify root directory (default /)")
    parser.add_argument("--ntp-conf", action="store", default="/etc/ntp.conf",
                        metavar="FILE", help="specify ntp config (default /etc/ntp.conf)")
    parser.add_argument("--step-tickers", action="store", default="",
                        metavar="FILE", help="specify ntpdate step-tickers config (no default)")
    parser.add_argument("--chrony-conf", action="store", default="/etc/chrony.conf",
                        metavar="FILE", help="specify chrony config (default /etc/chrony.conf)")
    parser.add_argument("--chrony-keys", action="store", default="/etc/chrony.keys",
                        metavar="FILE", help="specify chrony keyfile (default /etc/chrony.keys)")
    parser.add_argument("-b", "--backup", action="store_true", help="backup existing configs before writing")
    parser.add_argument("-L", "--ignored-lines", action="store_true", help="print ignored lines")
    parser.add_argument("-D", "--ignored-directives", action="store_true",
                        help="print names of ignored directives")
    parser.add_argument("-n", "--dry-run", action="store_true", help="don't make any changes")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")

    args = parser.parse_args()

    for root in args.roots:
        conf = NtpConfiguration(root, args.ntp_conf, args.step_tickers, args.verbose)

        if args.ignored_lines:
            for line in conf.ignored_lines:
                print(line)

        if args.ignored_directives:
            for directive in conf.ignored_directives:
                print(directive)

        conf.write_chrony_configuration(args.chrony_conf, args.chrony_keys, args.dry_run, args.backup)

if __name__ == "__main__":
    main()
