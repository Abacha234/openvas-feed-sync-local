# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890922");
  script_cve_id("CVE-2016-10200", "CVE-2016-2188", "CVE-2016-9604", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5970", "CVE-2017-6951", "CVE-2017-7184", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7472", "CVE-2017-7616", "CVE-2017-7618");
  script_tag(name:"creation_date", value:"2018-01-16 23:00:00 +0000 (Tue, 16 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 18:32:00 +0000 (Tue, 14 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-922)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-922");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-922");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-922 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or have other impacts.

CVE-2016-2188

Ralf Spenneberg of OpenSource Security reported that the iowarrior device driver did not sufficiently validate USB descriptors. This allowed a physically present user with a specially designed USB device to cause a denial of service (crash).

CVE-2016-9604

It was discovered that the keyring subsystem allowed a process to set a special internal keyring as its session keyring. The security impact in this version of the kernel is unknown.

CVE-2016-10200

Baozeng Ding and Andrey Konovalov reported a race condition in the L2TP implementation which could corrupt its table of bound sockets. A local user could use this to cause a denial of service (crash) or possibly for privilege escalation.

CVE-2017-2647 / CVE-2017-6951 idl3r reported that the keyring subsystem would allow a process to search for dead keys, causing a null pointer dereference. A local user could use this to cause a denial of service (crash).

CVE-2017-2671

Daniel Jiang discovered a race condition in the ping socket implementation. A local user with access to ping sockets could use this to cause a denial of service (crash) or possibly for privilege escalation. This feature is not accessible to any users by default.

CVE-2017-5967

Xing Gao reported that the /proc/timer_list file showed information about all processes, not considering PID namespaces. If timer debugging was enabled by a privileged user, this leaked information to processes contained in PID namespaces.

CVE-2017-5970

Andrey Konovalov discovered a denial-of-service flaw in the IPv4 networking code. This can be triggered by a local or remote attacker if a local UDP or raw socket has the IP_RETOPTS option enabled.

CVE-2017-7184

Chaitin Security Research Lab discovered that the net xfrm subsystem did not sufficiently validate replay state parameters, allowing a heap buffer overflow. This can be used by a local user with the CAP_NET_ADMIN capability for privilege escalation.

CVE-2017-7261

Vladis Dronov and Murray McAllister reported that the vmwgfx driver did not sufficiently validate rendering surface parameters. In a VMware guest, this can be used by a local user to cause a denial of service (crash).

CVE-2017-7273

Benoit Camredon reported that the hid-cypress driver did not sufficiently validate HID reports. This possibly allowed a physically present user with a specially designed USB device to cause a denial of service (crash).

CVE-2017-7294

Li Qiang reported that the vmwgfx driver did not sufficiently validate rendering surface parameters. In a VMware guest, this can be used by a local user to cause a denial of service (crash) or possibly for privilege escalation.

CVE-2017-7308

Andrey Konovalov reported that the packet socket (AF_PACKET) implementation did not sufficiently ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);