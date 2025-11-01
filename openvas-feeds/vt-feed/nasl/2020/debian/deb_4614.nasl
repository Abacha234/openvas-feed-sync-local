# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704614");
  script_cve_id("CVE-2019-18634");
  script_tag(name:"creation_date", value:"2020-02-02 04:00:12 +0000 (Sun, 02 Feb 2020)");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-07 17:15:00 +0000 (Fri, 07 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-4614)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4614");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4614");
  script_xref(name:"URL", value:"https://www.sudo.ws/alerts/pwfeedback.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sudo");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sudo' package(s) announced via the DSA-4614 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joe Vennix discovered a stack-based buffer overflow vulnerability in sudo, a program designed to provide limited super user privileges to specific users, triggerable when configured with the pwfeedback option enabled. An unprivileged user can take advantage of this flaw to obtain full root privileges.

Details can be found in the upstream advisory at [link moved to references].

For the oldstable distribution (stretch), this problem has been fixed in version 1.8.19p1-2.1+deb9u2.

For the stable distribution (buster), exploitation of the bug is prevented due to a change in EOF handling introduced in 1.8.26.

We recommend that you upgrade your sudo packages.

For the detailed security status of sudo please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'sudo' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);