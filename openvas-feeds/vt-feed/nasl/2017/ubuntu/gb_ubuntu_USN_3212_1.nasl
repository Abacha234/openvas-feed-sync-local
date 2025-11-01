# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843068");
  script_cve_id("CVE-2015-7554", "CVE-2015-8668", "CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10094", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-3632", "CVE-2016-3658", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5321", "CVE-2016-5322", "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-6223", "CVE-2016-8331", "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9448", "CVE-2016-9453", "CVE-2016-9532", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9539", "CVE-2016-9540", "CVE-2017-5225");
  script_tag(name:"creation_date", value:"2017-03-02 06:39:22 +0000 (Thu, 02 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3212-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3212-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the USN-3212-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LibTIFF incorrectly handled certain malformed
images. If a user or automated system were tricked into opening a specially
crafted image, a remote attacker could crash the application, leading to a
denial of service, or possibly execute arbitrary code with user privileges.");

  script_tag(name:"affected", value:"'tiff' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
