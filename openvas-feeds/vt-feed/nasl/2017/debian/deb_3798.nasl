# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703798");
  script_cve_id("CVE-2017-6307", "CVE-2017-6308", "CVE-2017-6309", "CVE-2017-6310");
  script_tag(name:"creation_date", value:"2017-02-28 23:00:00 +0000 (Tue, 28 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 17:56:00 +0000 (Wed, 13 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-3798)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3798");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3798");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tnef' package(s) announced via the DSA-3798 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eric Sesterhenn, from X41 D-Sec GmbH, discovered several vulnerabilities in tnef, a tool used to unpack MIME attachments of type application/ms-tnef. Multiple heap overflows, type confusions and out of bound reads and writes could be exploited by tricking a user into opening a malicious attachment. This would result in denial of service via application crash, or potential arbitrary code execution.

For the stable distribution (jessie), these problems have been fixed in version 1.4.9-1+deb8u1.

We recommend that you upgrade your tnef packages.");

  script_tag(name:"affected", value:"'tnef' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);