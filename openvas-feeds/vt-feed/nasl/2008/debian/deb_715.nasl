# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53543");
  script_cve_id("CVE-2004-1342", "CVE-2004-1343");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-715)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-715");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-715");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cvs' package(s) announced via the DSA-715 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in the CVS server, which serves the popular Concurrent Versions System. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2004-1342

Maks Polunin and Alberto Garcia discovered independently that using the pserver access method in connection with the repouid patch that Debian uses it is possible to bypass the password and gain access to the repository in question.

CAN-2004-1343

Alberto Garcia discovered that a remote user can cause the cvs server to crash when the cvs-repouids file exists but does not contain a mapping for the current repository, which can be used as a denial of service attack.

For the stable distribution (woody) these problems have been fixed in version 1.11.1p1debian-10.

For the unstable distribution (sid) these problems have been fixed in version 1.12.9-11.

We recommend that you upgrade your cvs package.");

  script_tag(name:"affected", value:"'cvs' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);