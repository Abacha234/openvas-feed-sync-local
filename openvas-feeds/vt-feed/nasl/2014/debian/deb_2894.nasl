# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702894");
  script_cve_id("CVE-2014-2532", "CVE-2014-2653");
  script_tag(name:"creation_date", value:"2014-04-04 22:00:00 +0000 (Fri, 04 Apr 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)");

  script_name("Debian: Security Advisory (DSA-2894)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2894");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2894");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-2894 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in OpenSSH, an implementation of the SSH protocol suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-2532

Jann Horn discovered that OpenSSH incorrectly handled wildcards in AcceptEnv lines. A remote attacker could use this issue to trick OpenSSH into accepting any environment variable that contains the characters before the wildcard character.

CVE-2014-2653

Matthew Vernon reported that if a SSH server offers a HostCertificate that the ssh client doesn't accept, then the client doesn't check the DNS for SSHFP records. As a consequence a malicious server can disable SSHFP-checking by presenting a certificate.

Note that a host verification prompt is still displayed before connecting.

For the oldstable distribution (squeeze), these problems have been fixed in version 1:5.5p1-6+squeeze5.

For the stable distribution (wheezy), these problems have been fixed in version 1:6.0p1-4+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 1:6.6p1-1.

We recommend that you upgrade your openssh packages.");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);