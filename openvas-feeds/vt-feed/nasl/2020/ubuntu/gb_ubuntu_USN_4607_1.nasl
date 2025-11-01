# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844681");
  script_cve_id("CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14798", "CVE-2020-14803");
  script_tag(name:"creation_date", value:"2020-10-28 04:01:02 +0000 (Wed, 28 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 21:42:00 +0000 (Wed, 24 Feb 2021)");

  script_name("Ubuntu: Security Advisory (USN-4607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4607-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4607-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8, openjdk-lts' package(s) announced via the USN-4607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenJDK incorrectly handled deserializing Proxy
class objects with many interfaces. A remote attacker could possibly use
this issue to cause a denial of service (memory consumption) via a
specially crafted input. (CVE-2020-14779)

Sergey Ostanin discovered that OpenJDK incorrectly restricted
authentication mechanisms. A remote attacker could possibly use this
issue to obtain sensitive information over an unencrypted connection.
(CVE-2020-14781)

It was discovered that OpenJDK incorrectly handled untrusted certificates.
An attacker could possibly use this issue to read or write sensitive
information. (CVE-2020-14782)

Zhiqiang Zang discovered that OpenJDK incorrectly checked for integer
overflows. An attacker could possibly use this issue to bypass certain
Java sandbox restrictions. (CVE-2020-14792)

Markus Loewe discovered that OpenJDK incorrectly checked permissions when
converting a file system path to an URI. An attacker could possibly use
this issue to bypass certain Java sandbox restrictions. (CVE-2020-14796)

Markus Loewe discovered that OpenJDK incorrectly checked for invalid
characters when converting an URI to a path. An attacker could possibly
use this issue to read or write sensitive information. (CVE-2020-14797)

Markus Loewe discovered that OpenJDK incorrectly checked the length of
input strings. An attacker could possibly use this issue to bypass certain
Java sandbox restrictions. (CVE-2020-14798)

It was discovered that OpenJDK incorrectly handled boundary checks. An
attacker could possibly use this issue to bypass certain Java sandbox
restrictions. (CVE-2020-14803)");

  script_tag(name:"affected", value:"'openjdk-8, openjdk-lts' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
