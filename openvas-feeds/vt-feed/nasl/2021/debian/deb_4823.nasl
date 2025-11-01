# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704823");
  script_cve_id("CVE-2019-20933");
  script_tag(name:"creation_date", value:"2021-01-03 04:03:00 +0000 (Sun, 03 Jan 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-02 16:15:00 +0000 (Sat, 02 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4823)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4823");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4823");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/influxdb");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'influxdb' package(s) announced via the DSA-4823 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that incorrect validation of JWT tokens in InfluxDB, a time series, metrics, and analytics database, could result in authentication bypass.

For the stable distribution (buster), this problem has been fixed in version 1.6.4-1+deb10u1.

We recommend that you upgrade your influxdb packages.

For the detailed security status of influxdb please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'influxdb' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);