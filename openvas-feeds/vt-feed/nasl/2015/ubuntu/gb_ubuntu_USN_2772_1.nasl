# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842490");
  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_tag(name:"creation_date", value:"2015-10-16 07:26:55 +0000 (Fri, 16 Oct 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2772-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2772-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-9.1, postgresql-9.3, postgresql-9.4' package(s) announced via the USN-2772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Josh Kupershmidt discovered the pgCrypto extension could expose
several bytes of server memory if the crypt() function was provided a
too-short salt. An attacker could use this flaw to read private data.
(CVE-2015-5288)

Oskari Saarenmaa discovered that the json and jsonb handlers could exhaust
available stack space. An attacker could use this flaw to perform a denial
of service attack. This issue only affected Ubuntu 14.04 LTS and Ubuntu
15.04. (CVE-2015-5289)");

  script_tag(name:"affected", value:"'postgresql-9.1, postgresql-9.3, postgresql-9.4' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
