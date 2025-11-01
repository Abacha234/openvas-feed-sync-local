# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53233");
  script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-543)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-543");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-543");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-543 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The MIT Kerberos Development Team has discovered a number of vulnerabilities in the MIT Kerberos Version 5 software. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2004-0642 [VU#795632] A double-free error may allow unauthenticated remote attackers to execute arbitrary code on KDC or clients. CAN-2004-0643 [VU#866472] Several double-free errors may allow authenticated attackers to execute arbitrary code on Kerberos application servers. CAN-2004-0644 [VU#550464] A remotely exploitable denial of service vulnerability has been found in the KDC and libraries. CAN-2004-0772 [VU#350792] Several double-free errors may allow remote attackers to execute arbitrary code on the server. This does not affect the version in woody.

For the stable distribution (woody) these problems have been fixed in version 1.2.4-5woody6.

For the unstable distribution (sid) these problems have been fixed in version 1.3.4-3.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);