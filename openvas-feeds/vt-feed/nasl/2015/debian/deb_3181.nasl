# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703181");
  script_cve_id("CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151");
  script_tag(name:"creation_date", value:"2015-03-09 23:00:00 +0000 (Mon, 09 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3181)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3181");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3181");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3181 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Xen virtualisation solution:

CVE-2015-2044

Information leak via x86 system device emulation.

CVE-2015-2045

Information leak in the HYPERVISOR_xen_version() hypercall.

CVE-2015-2151

Missing input sanitising in the x86 emulator could result in information disclosure, denial of service or potentially privilege escalation.

In addition the Xen developers reported an unfixable limitation in the handling of non-standard PCI devices. Please refer to for further information.

For the stable distribution (wheezy), these problems have been fixed in version 4.1.4-3+deb7u5.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);