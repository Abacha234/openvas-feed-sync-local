# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843247");
  script_cve_id("CVE-2014-9900", "CVE-2016-9755", "CVE-2017-1000380", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-7346", "CVE-2017-7895", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9150", "CVE-2017-9605");
  script_tag(name:"creation_date", value:"2017-07-21 05:18:04 +0000 (Fri, 21 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3359-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3359-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3359-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-raspi2' package(s) announced via the USN-3359-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly initialize a Wake-
on-Lan data structure. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2014-9900)

Dmitry Vyukov, Andrey Konovalov, Florian Westphal, and Eric Dumazet
discovered that the netfiler subsystem in the Linux kernel mishandled IPv6
packet reassembly. A local user could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2016-9755)

Alexander Potapenko discovered a race condition in the Advanced Linux Sound
Architecture (ALSA) subsystem in the Linux kernel. A local attacker could
use this to expose sensitive information (kernel memory).
(CVE-2017-1000380)

It was discovered that the Linux kernel did not clear the setgid bit during
a setxattr call on a tmpfs filesystem. A local attacker could use this to
gain elevated group privileges. (CVE-2017-5551)

Murray McAllister discovered that an integer overflow existed in the
VideoCore DRM driver of the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-5576)

Li Qiang discovered that the DRM driver for VMware Virtual GPUs in the
Linux kernel did not properly validate some ioctl arguments. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-7346)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3 server
implementations in the Linux kernel did not properly check for the end of
buffer. A remote attacker could use this to craft requests that cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-7895)

It was discovered that an integer underflow existed in the Edgeport USB
Serial Converter device driver of the Linux kernel. An attacker with
physical access could use this to expose sensitive information (kernel
memory). (CVE-2017-8924)

It was discovered that the USB ZyXEL omni.net LCD PLUS driver in the Linux
kernel did not properly perform reference counting. A local attacker could
use this to cause a denial of service (tty exhaustion). (CVE-2017-8925)

Jann Horn discovered that bpf in Linux kernel does not restrict the output
of the print_bpf_insn function. A local attacker could use this to obtain
sensitive address information. (CVE-2017-9150)

Murray McAllister discovered that the DRM driver for VMware Virtual GPUs in
the Linux kernel did not properly initialize memory. A local attacker could
use this to expose sensitive information (kernel memory). (CVE-2017-9605)");

  script_tag(name:"affected", value:"'linux, linux-raspi2' package(s) on Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
