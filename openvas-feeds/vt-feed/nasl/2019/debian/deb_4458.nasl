# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704458");
  script_cve_id("CVE-2019-11356");
  script_tag(name:"creation_date", value:"2019-06-09 02:00:05 +0000 (Sun, 09 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-03 14:27:00 +0000 (Tue, 03 May 2022)");

  script_name("Debian: Security Advisory (DSA-4458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4458");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4458");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cyrus-imapd");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-imapd' package(s) announced via the DSA-4458 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the CalDAV feature in httpd of the Cyrus IMAP server, leading to denial of service or potentially the execution of arbitrary code via a crafted HTTP PUT operation for an event with a long iCalendar property name.

For the stable distribution (stretch), this problem has been fixed in version 2.5.10-3+deb9u1.

We recommend that you upgrade your cyrus-imapd packages.

For the detailed security status of cyrus-imapd please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cyrus-imapd' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);