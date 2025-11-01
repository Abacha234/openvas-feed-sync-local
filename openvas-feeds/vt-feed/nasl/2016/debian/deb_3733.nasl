# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703733");
  script_cve_id("CVE-2016-1252");
  script_tag(name:"creation_date", value:"2016-12-12 23:00:00 +0000 (Mon, 12 Dec 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:26:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-3733)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3733");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3733");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apt' package(s) announced via the DSA-3733 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn of Google Project Zero discovered that APT, the high level package manager, does not properly handle errors when validating signatures on InRelease files. An attacker able to man-in-the-middle HTTP requests to an apt repository that uses InRelease files (clearsigned Release files), can take advantage of this flaw to circumvent the signature of the InRelease file, leading to arbitrary code execution.

For the stable distribution (jessie), this problem has been fixed in version 1.0.9.8.4.

For the unstable distribution (sid), this problem has been fixed in version 1.4~beta2.

We recommend that you upgrade your apt packages.");

  script_tag(name:"affected", value:"'apt' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);