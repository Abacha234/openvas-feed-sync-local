# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71479");
  script_cve_id("CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934");
  script_tag(name:"creation_date", value:"2012-08-10 07:07:04 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2501)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2501");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2501");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2501 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Xen, a hypervisor.

CVE-2012-0217

Xen does not properly handle uncanonical return addresses on Intel amd64 CPUs, allowing amd64 PV guests to elevate to hypervisor privileges. AMD processors, HVM and i386 guests are not affected.

CVE-2012-0218

Xen does not properly handle SYSCALL and SYSENTER instructions in PV guests, allowing unprivileged users inside a guest system to crash the guest system.

CVE-2012-2934

Xen does not detect old AMD CPUs affected by AMD Erratum #121.

For CVE-2012-2934, Xen refuses to start domUs on affected systems unless the allow_unsafe option is passed.

For the stable distribution (squeeze), these problems have been fixed in version 4.0.1-5.2.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 4.1.3~rc1+hg-20120614.a9c0a89c08f2-1.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);