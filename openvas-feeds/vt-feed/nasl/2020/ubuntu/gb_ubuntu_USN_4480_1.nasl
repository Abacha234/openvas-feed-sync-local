# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844560");
  script_cve_id("CVE-2020-12689", "CVE-2020-12690", "CVE-2020-12691", "CVE-2020-12692");
  script_tag(name:"creation_date", value:"2020-09-02 06:21:28 +0000 (Wed, 02 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 05:15:00 +0000 (Tue, 13 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4480-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4480-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keystone' package(s) announced via the USN-4480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenStack Keystone incorrectly handled EC2
credentials. An authenticated attacker with a limited scope could possibly
create EC2 credentials with escalated permissions. (CVE-2020-12689,
CVE-2020-12691)

It was discovered that OpenStack Keystone incorrectly handled the list of
roles provided with OAuth1 access tokens. An authenticated user could
possibly end up with more role assignments than intended. (CVE-2020-12690)

It was discovered that OpenStack Keystone incorrectly handled EC2 signature
TTL checks. A remote attacker could possibly use this issue to reuse
Authorization headers. (CVE-2020-12692)");

  script_tag(name:"affected", value:"'keystone' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
