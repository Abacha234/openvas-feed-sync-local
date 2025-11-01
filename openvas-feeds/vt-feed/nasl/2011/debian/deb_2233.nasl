# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69733");
  script_cve_id("CVE-2011-0411", "CVE-2011-1720");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2233)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2233");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2233");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postfix' package(s) announced via the DSA-2233 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Postfix, a mail transfer agent. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2939

The postinst script grants the postfix user write access to /var/spool/postfix/pid, which might allow local users to conduct symlink attacks that overwrite arbitrary files.

CVE-2011-0411

The STARTTLS implementation does not properly restrict I/O buffering, which allows man-in-the-middle attackers to insert commands into encrypted SMTP sessions by sending a cleartext command that is processed after TLS is in place.

CVE-2011-1720

A heap-based read-only buffer overflow allows malicious clients to crash the smtpd server process using a crafted SASL authentication request.

For the oldstable distribution (lenny), this problem has been fixed in version 2.5.5-1.1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 2.7.1-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 2.8.0-1.

We recommend that you upgrade your postfix packages.");

  script_tag(name:"affected", value:"'postfix' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);