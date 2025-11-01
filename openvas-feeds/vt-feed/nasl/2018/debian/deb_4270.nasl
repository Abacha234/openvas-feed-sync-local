# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704270");
  script_cve_id("CVE-2018-14424");
  script_tag(name:"creation_date", value:"2018-08-12 22:00:00 +0000 (Sun, 12 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-18 20:21:00 +0000 (Thu, 18 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-4270)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4270");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4270");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gdm3");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gdm3' package(s) announced via the DSA-4270 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Coulson discovered a use-after-free flaw in the GNOME Display Manager, triggerable by an unprivileged user via a specially crafted sequence of D-Bus method calls, leading to denial of service or potentially the execution of arbitrary code.

For the stable distribution (stretch), this problem has been fixed in version 3.22.3-3+deb9u2.

We recommend that you upgrade your gdm3 packages.

For the detailed security status of gdm3 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gdm3' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);