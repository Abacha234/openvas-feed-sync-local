# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844168");
  script_cve_id("CVE-2018-20406", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948");
  script_tag(name:"creation_date", value:"2019-09-10 02:00:47 +0000 (Tue, 10 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-05 18:53:00 +0000 (Tue, 05 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-4127-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4127-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4127-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.5, python3.6, python3.7' package(s) announced via the USN-4127-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python incorrectly handled certain pickle files. An
attacker could possibly use this issue to consume memory, leading to a
denial of service. This issue only affected Ubuntu 16.04 LTS and Ubuntu
18.04 LTS. (CVE-2018-20406)

It was discovered that Python incorrectly validated the domain when
handling cookies. An attacker could possibly trick Python into sending
cookies to the wrong domain. (CVE-2018-20852)

Jonathan Birch and Panayiotis Panayiotou discovered that Python incorrectly
handled Unicode encoding during NFKC normalization. An attacker could
possibly use this issue to obtain sensitive information. (CVE-2019-9636,
CVE-2019-10160)

Colin Read and Nicolas Edet discovered that Python incorrectly handled
parsing certain X509 certificates. An attacker could possibly use this
issue to cause Python to crash, resulting in a denial of service. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-5010)

It was discovered that Python incorrectly handled certain urls. A remote
attacker could possibly use this issue to perform CRLF injection attacks.
(CVE-2019-9740, CVE-2019-9947)

Sihoon Lee discovered that Python incorrectly handled the local_file:
scheme. A remote attacker could possibly use this issue to bypass blocklist
meschanisms. (CVE-2019-9948)");

  script_tag(name:"affected", value:"'python2.7, python3.5, python3.6, python3.7' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
