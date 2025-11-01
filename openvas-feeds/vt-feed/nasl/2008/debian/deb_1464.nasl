# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60207");
  script_cve_id("CVE-2007-6437");
  script_tag(name:"creation_date", value:"2008-01-31 15:11:48 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1464)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1464");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1464");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'syslog-ng' package(s) announced via the DSA-1464 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Oriol Carreras discovered that syslog-ng, a next generation logging daemon can be tricked into dereferencing a NULL pointer through malformed timestamps, which can lead to denial of service and the disguise of an subsequent attack, which would otherwise be logged.

The old stable distribution (sarge) is not affected.

For the stable distribution (etch), this problem has been fixed in version 2.0.0-1etch1.

For the unstable distribution (sid), this problem has been fixed in version 2.0.6-1.

We recommend that you upgrade your syslog-ng package.");

  script_tag(name:"affected", value:"'syslog-ng' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);