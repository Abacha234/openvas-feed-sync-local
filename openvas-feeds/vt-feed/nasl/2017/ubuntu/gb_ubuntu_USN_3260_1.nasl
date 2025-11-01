# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843135");
  script_cve_id("CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5453", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5458", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5468", "CVE-2017-5469");
  script_tag(name:"creation_date", value:"2017-04-22 04:45:04 +0000 (Sat, 22 Apr 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 18:44:00 +0000 (Tue, 07 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3260-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3260-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, obtain sensitive
information, spoof the addressbar contents or other UI elements, escape
the sandbox to read local files, conduct cross-site scripting (XSS)
attacks, cause a denial of service via application crash, or execute
arbitrary code. (CVE-2017-5429, CVE-2017-5430, CVE-2017-5432,
CVE-2017-5433, CVE-2017-5434, CVE-2017-5435, CVE-2017-5436, CVE-2017-5437,
CVE-2017-5438, CVE-2017-5439, CVE-2017-5440, CVE-2017-5441, CVE-2017-5442,
CVE-2017-5443, CVE-2017-5444, CVE-2017-5445, CVE-2017-5446, CVE-2017-5447,
CVE-2017-5448, CVE-2017-5449, CVE-2017-5451, CVE-2017-5453, CVE-2017-5454,
CVE-2017-5455, CVE-2017-5456, CVE-2017-5458, CVE-2017-5459, CVE-2017-5460,
CVE-2017-5461, CVE-2017-5464, CVE-2017-5465, CVE-2017-5466, CVE-2017-5467,
CVE-2017-5468, CVE-2017-5469)

A flaw was discovered in the DRBG number generation in NSS. If an
attacker were able to perform a machine-in-the-middle attack, this flaw
could potentially be exploited to view sensitive information.
(CVE-2017-5462)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
