# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703861");
  script_cve_id("CVE-2017-6891");
  script_tag(name:"creation_date", value:"2017-05-23 22:00:00 +0000 (Tue, 23 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-03 19:05:00 +0000 (Fri, 03 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-3861)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3861");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3861");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtasn1-6' package(s) announced via the DSA-3861 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Jirasek of Secunia Research discovered that libtasn1, a library used to handle Abstract Syntax Notation One structures, did not properly validate its input. This would allow an attacker to cause a crash by denial-of-service, or potentially execute arbitrary code, by tricking a user into processing a maliciously crafted assignments file.

For the stable distribution (jessie), this problem has been fixed in version 4.2-3+deb8u3.

We recommend that you upgrade your libtasn1-6 packages.");

  script_tag(name:"affected", value:"'libtasn1-6' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);