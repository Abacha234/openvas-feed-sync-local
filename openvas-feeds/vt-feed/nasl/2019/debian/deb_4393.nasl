# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704393");
  script_cve_id("CVE-2019-6454");
  script_tag(name:"creation_date", value:"2019-02-17 23:00:00 +0000 (Sun, 17 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-20 06:08:00 +0000 (Sun, 20 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-4393)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4393");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4393");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/systemd");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'systemd' package(s) announced via the DSA-4393 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Coulson discovered a flaw in systemd leading to denial of service. An unprivileged user could take advantage of this issue to crash PID1 by sending a specially crafted D-Bus message on the system bus.

For the stable distribution (stretch), this problem has been fixed in version 232-25+deb9u9.

We recommend that you upgrade your systemd packages.

For the detailed security status of systemd please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'systemd' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);