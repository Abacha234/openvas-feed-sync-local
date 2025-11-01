# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845502");
  script_cve_id("CVE-2021-33656");
  script_tag(name:"creation_date", value:"2022-09-02 01:00:30 +0000 (Fri, 02 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 13:44:00 +0000 (Thu, 28 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5591-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5591-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5591-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-azure-4.15, linux-dell300x, linux-gcp-4.15, linux-kvm, linux-meta, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-snapdragon, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-snapdragon' package(s) announced via the USN-5591-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the virtual terminal driver in the Linux kernel did
not properly handle VGA console font changes, leading to an out-of-bounds
write. A local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'linux, linux-azure-4.15, linux-dell300x, linux-gcp-4.15, linux-kvm, linux-meta, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-snapdragon, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-snapdragon' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
