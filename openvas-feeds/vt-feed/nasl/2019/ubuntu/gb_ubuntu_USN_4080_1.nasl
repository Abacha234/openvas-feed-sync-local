# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844116");
  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2842", "CVE-2019-7317");
  script_tag(name:"creation_date", value:"2019-08-01 02:01:11 +0000 (Thu, 01 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-25 14:09:00 +0000 (Mon, 25 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-4080-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4080-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4080-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8' package(s) announced via the USN-4080-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Keegan Ryan discovered that the ECC implementation in OpenJDK was not
sufficiently resilient to side-channel attacks. An attacker could possibly
use this to expose sensitive information. (CVE-2019-2745)

It was discovered that OpenJDK did not sufficiently validate serial streams
before deserializing suppressed exceptions in some situations. An attacker
could use this to specially craft an object that, when deserialized, would
cause a denial of service. (CVE-2019-2762)

It was discovered that in some situations OpenJDK did not properly bound
the amount of memory allocated during object deserialization. An attacker
could use this to specially craft an object that, when deserialized, would
cause a denial of service (excessive memory consumption). (CVE-2019-2769)

It was discovered that OpenJDK did not properly restrict privileges in
certain situations. An attacker could use this to specially construct an
untrusted Java application or applet that could escape sandbox
restrictions. (CVE-2019-2786)

Jonathan Birch discovered that the Networking component of OpenJDK did not
properly validate URLs in some situations. An attacker could use this to
bypass restrictions on characters in URLs. (CVE-2019-2816)

Nati Nimni discovered that the Java Cryptography Extension component in
OpenJDK did not properly perform array bounds checking in some situations.
An attacker could use this to cause a denial of service. (CVE-2019-2842)

It was discovered that OpenJDK incorrectly handled certain memory
operations. If a user or automated system were tricked into opening a
specially crafted PNG file, a remote attacker could use this issue to
cause OpenJDK to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2019-7317)");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
