# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703396");
  script_cve_id("CVE-2015-5307", "CVE-2015-7833", "CVE-2015-7872", "CVE-2015-7990");
  script_tag(name:"creation_date", value:"2015-11-09 23:00:00 +0000 (Mon, 09 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-17 01:29:00 +0000 (Wed, 17 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3396)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3396");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3396");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3396 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service.

CVE-2015-5307

Ben Serebrin from Google discovered a guest to host denial of service flaw affecting the KVM hypervisor. A malicious guest can trigger an infinite stream of alignment check (#AC) exceptions causing the processor microcode to enter an infinite loop where the core never receives another interrupt. This leads to a panic of the host kernel.

CVE-2015-7833

Sergej Schumilo, Hendrik Schwartke and Ralf Spenneberg discovered a flaw in the processing of certain USB device descriptors in the usbvision driver. An attacker with physical access to the system can use this flaw to crash the system.

CVE-2015-7872

Dmitry Vyukov discovered a vulnerability in the keyrings garbage collector allowing a local user to trigger a kernel panic.

CVE-2015-7990

It was discovered that the fix for CVE-2015-6937 was incomplete. A race condition when sending a message on unbound socket can still cause a NULL pointer dereference. A remote attacker might be able to cause a denial of service (crash) by sending a crafted packet.

For the oldstable distribution (wheezy), these problems have been fixed in version 3.2.68-1+deb7u6.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt11-1+deb8u6.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);