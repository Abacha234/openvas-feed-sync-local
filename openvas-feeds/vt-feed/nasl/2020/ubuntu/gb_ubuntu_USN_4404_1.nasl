# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844479");
  script_cve_id("CVE-2020-5963", "CVE-2020-5967", "CVE-2020-5973");
  script_tag(name:"creation_date", value:"2020-06-26 03:00:18 +0000 (Fri, 26 Jun 2020)");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-13 19:58:00 +0000 (Mon, 13 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4404-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4404-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4404-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-graphics-drivers-390, nvidia-graphics-drivers-440' package(s) announced via the USN-4404-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas E. Carroll discovered that the NVIDIA Cuda graphics driver did not
properly perform access control when performing IPC. An attacker could use
this to cause a denial of service or possibly execute arbitrary code.
(CVE-2020-5963)

It was discovered that the UVM driver in the NVIDIA graphics driver
contained a race condition. A local attacker could use this to cause a
denial of service. (CVE-2020-5967)

It was discovered that the NVIDIA virtual GPU guest drivers contained
an unspecified vulnerability that could potentially lead to privileged
operation execution. An attacker could use this to cause a denial of
service. (CVE-2020-5973)");

  script_tag(name:"affected", value:"'nvidia-graphics-drivers-390, nvidia-graphics-drivers-440' package(s) on Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
