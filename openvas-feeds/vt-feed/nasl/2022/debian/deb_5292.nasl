# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705292");
  script_cve_id("CVE-2022-3328");
  script_tag(name:"creation_date", value:"2022-12-02 11:04:54 +0000 (Fri, 02 Dec 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5292");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5292");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/snapd");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'snapd' package(s) announced via the DSA-5292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Research Team discovered a race condition in the snapd-confine binary which could result in local privilege escalation.

For the stable distribution (bullseye), this problem has been fixed in version 2.49-1+deb11u2.

We recommend that you upgrade your snapd packages.

For the detailed security status of snapd please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'snapd' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);