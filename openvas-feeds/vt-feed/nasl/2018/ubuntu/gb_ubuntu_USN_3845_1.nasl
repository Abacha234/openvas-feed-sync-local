# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843855");
  script_cve_id("CVE-2018-8784", "CVE-2018-8785", "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789");
  script_tag(name:"creation_date", value:"2018-12-13 06:30:11 +0000 (Thu, 13 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 16:29:00 +0000 (Mon, 03 Jun 2019)");

  script_name("Ubuntu: Security Advisory (USN-3845-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3845-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3845-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp, freerdp2' package(s) announced via the USN-3845-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eyal Itkin discovered FreeRDP incorrectly handled certain stream encodings. A
malicious server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only applies
to Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8784, CVE-2018-8785)

Eyal Itkin discovered FreeRDP incorrectly handled bitmaps. A malicious server
could use this issue to cause FreeRDP to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2018-8786, CVE-2018-8787)

Eyal Itkin discovered FreeRDP incorrectly handled certain stream encodings. A
malicious server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only applies
to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8788)

Eyal Itkin discovered FreeRDP incorrectly handled NTLM authentication. A
malicious server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only applies
to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8789)");

  script_tag(name:"affected", value:"'freerdp, freerdp2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
