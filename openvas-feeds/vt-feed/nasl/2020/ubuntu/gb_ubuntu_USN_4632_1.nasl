# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844714");
  script_cve_id("CVE-2020-7039", "CVE-2020-8608");
  script_tag(name:"creation_date", value:"2020-11-13 04:00:32 +0000 (Fri, 13 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-14 03:50:00 +0000 (Sun, 14 Feb 2021)");

  script_name("Ubuntu: Security Advisory (USN-4632-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4632-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4632-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slirp' package(s) announced via the USN-4632-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SLiRP networking implementation of the QEMU
emulator did not properly manage memory under certain circumstances. An
attacker could use this to cause a heap-based buffer overflow or other out-
of-bounds access, which can lead to a denial of service (application crash)
or potentially execute arbitrary code. (CVE-2020-7039)

It was discovered that the SLiRP networking implementation of the QEMU
emulator misuses snprintf return values. An attacker could use this to
cause a denial of service (application crash) or potentially execute
arbitrary code. (CVE-2020-8608)");

  script_tag(name:"affected", value:"'slirp' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
