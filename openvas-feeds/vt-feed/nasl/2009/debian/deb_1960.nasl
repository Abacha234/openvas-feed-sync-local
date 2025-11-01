# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66595");
  script_cve_id("CVE-2009-4235");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1960)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1960");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1960");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'acpid' package(s) announced via the DSA-1960 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that acpid, the Advanced Configuration and Power Interface event daemon, on the oldstable distribution (etch) creates its log file with weak permissions, which might expose sensitive information or might be abused by a local user to consume all free disk space on the same partition of the file.

For the oldstable distribution (etch), this problem has been fixed in version 1.0.4-5etch2.

The stable distribution (lenny) in version 1.0.8-1lenny2 and the unstable distribution (sid) in version 1.0.10-5, have been updated to fix the weak file permissions of the log file created by older versions.

We recommend that you upgrade your acpid packages.");

  script_tag(name:"affected", value:"'acpid' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);