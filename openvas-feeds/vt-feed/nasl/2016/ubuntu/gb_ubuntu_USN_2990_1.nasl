# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842781");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718", "CVE-2016-5118");
  script_tag(name:"creation_date", value:"2016-06-03 03:28:40 +0000 (Fri, 03 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-2990-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2990-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2990-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-2990-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nikolay Ermishkin and Stewie discovered that ImageMagick incorrectly
sanitized untrusted input. A remote attacker could use these issues to
execute arbitrary code. These issues are known as 'ImageTragick'. This
update disables problematic coders via the /etc/ImageMagick-6/policy.xml
configuration file. In certain environments the coders may need to be
manually re-enabled after making sure that ImageMagick does not process
untrusted input. (CVE-2016-3714, CVE-2016-3715, CVE-2016-3716,
CVE-2016-3717, CVE-2016-3718)

Bob Friesenhahn discovered that ImageMagick allowed injecting commands via
an image file or filename. A remote attacker could use this issue to
execute arbitrary code. (CVE-2016-5118)");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
