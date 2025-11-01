# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704339");
  script_cve_id("CVE-2017-7519", "CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129");
  script_tag(name:"creation_date", value:"2018-11-12 23:00:00 +0000 (Mon, 12 Nov 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4339)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4339");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4339");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ceph");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ceph' package(s) announced via the DSA-4339 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Ceph, a distributed storage and file system: The cephx authentication protocol was suspectible to replay attacks and calculated signatures incorrectly, ceph mon did not validate capabilities for pool operations (resulting in potential corruption or deletion of snapshot images) and a format string vulnerability in libradosstriper could result in denial of service.

For the stable distribution (stretch), these problems have been fixed in version 10.2.11-1.

We recommend that you upgrade your ceph packages.

For the detailed security status of ceph please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ceph' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);