# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703285");
  script_cve_id("CVE-2015-3209", "CVE-2015-4037");
  script_tag(name:"creation_date", value:"2015-06-12 22:00:00 +0000 (Fri, 12 Jun 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3285)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3285");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3285");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu-kvm' package(s) announced via the DSA-3285 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in qemu-kvm, a full virtualization solution on x86 hardware.

CVE-2015-3209

Matt Tait of Google's Project Zero security team discovered a flaw in the way QEMU's AMD PCnet Ethernet emulation handles multi-TMD packets with a length above 4096 bytes. A privileged guest user in a guest with an AMD PCNet ethernet card enabled can potentially use this flaw to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2015-4037

Kurt Seifried of Red Hat Product Security discovered that QEMU's user mode networking stack uses predictable temporary file names when the -smb option is used. An unprivileged user can use this flaw to cause a denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.1.2+dfsg-6+deb7u8.

We recommend that you upgrade your qemu-kvm packages.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);