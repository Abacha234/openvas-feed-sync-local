# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704225");
  script_cve_id("CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815");
  script_tag(name:"creation_date", value:"2018-06-09 22:00:00 +0000 (Sat, 09 Jun 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Debian: Security Advisory (DSA-4225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4225");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4225");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openjdk-7");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-7' package(s) announced via the DSA-4225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Oracle Java platform, resulting in denial of service, sandbox bypass, execution of arbitrary code or bypass of JAR signature validation.

For the oldstable distribution (jessie), these problems have been fixed in version 7u181-2.6.14-1~deb8u1.

We recommend that you upgrade your openjdk-7 packages.

For the detailed security status of openjdk-7 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);