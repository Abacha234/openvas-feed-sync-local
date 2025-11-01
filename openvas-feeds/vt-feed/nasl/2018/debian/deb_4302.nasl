# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704302");
  script_cve_id("CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949");
  script_tag(name:"creation_date", value:"2018-09-22 22:00:00 +0000 (Sat, 22 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4302");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4302");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openafs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DSA-4302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in openafs, an implementation of the distributed filesystem AFS. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2018-16947

Jeffrey Altman reported that the backup tape controller (butc) process does accept incoming RPCs but does not require (or allow for) authentication of those RPCs, allowing an unauthenticated attacker to perform volume operations with administrator credentials.


CVE-2018-16948

Mark Vitale reported that several RPC server routines do not fully initialize output variables, leaking memory contents (from both the stack and the heap) to the remote caller for otherwise-successful RPCs.


CVE-2018-16949

Mark Vitale reported that an unauthenticated attacker can consume large amounts of server memory and network bandwidth via specially crafted requests, resulting in denial of service to legitimate clients.


For the stable distribution (stretch), these problems have been fixed in version 1.6.20-2+deb9u2.

We recommend that you upgrade your openafs packages.

For the detailed security status of openafs please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);