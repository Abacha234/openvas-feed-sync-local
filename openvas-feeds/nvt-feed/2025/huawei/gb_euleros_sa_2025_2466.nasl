# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2466");
  script_cve_id("CVE-2025-8534", "CVE-2025-8851", "CVE-2025-9165", "CVE-2025-9900");
  script_tag(name:"creation_date", value:"2025-12-11 12:41:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-23 17:15:38 +0000 (Tue, 23 Sep 2025)");

  script_name("Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2025-2466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2466");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2466");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtiff' package(s) announced via the EulerOS-SA-2025-2466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability classified as problematic was found in libtiff 4.6.0. This vulnerability affects the function PS_Lvl2page of the file tools/tiff2ps.c of the component tiff2ps. The manipulation leads to null pointer dereference. It is possible to launch the attack on the local host. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is 6ba36f159fd396ad11bf6b7874554197736ecc8b. It is recommended to apply a patch to fix this issue. One of the maintainers explains, that '[t]his error only occurs if DEFER_STRILE_LOAD (defer-strile-load:BOOL=ON) or TIFFOpen( .. 'rD') option is used.'(CVE-2025-8534)

A vulnerability was determined in LibTIFF up to 4.5.1. Affected by this issue is the function readSeparateStripsetoBuffer of the file tools/tiffcrop.c of the component tiffcrop. The manipulation leads to stack-based buffer overflow. Local access is required to approach this attack. The patch is identified as 8a7a48d7a645992ca83062b3a1873c951661e2b3. It is recommended to apply a patch to fix this issue.(CVE-2025-8851)

A flaw has been found in LibTIFF 4.7.0. This affects the function _TIFFmallocExt/_TIFFCheckRealloc/TIFFHashSetNew/InitCCITTFax3 of the file tools/tiffcmp.c of the component tiffcmp. Executing manipulation can lead to memory leak. The attack is restricted to local execution. This attack is characterized by high complexity. It is indicated that the exploitability is difficult. The exploit has been published and may be used. There is ongoing doubt regarding the real existence of this vulnerability. This patch is called ed141286a37f6e5ddafb5069347ff5d587e7a4e0. It is best practice to apply a patch to resolve this issue. A researcher disputes the security impact of this issue, because 'this is a memory leak on a command line tool that is about to exit anyway'. In the reply the project maintainer declares this issue as 'a simple 'bug' when leaving the command line tool and (...) not a security issue at all'.(CVE-2025-9165)

A flaw was found in Libtiff. This vulnerability is a 'write-what-where' condition, triggered when the library processes a specially crafted TIFF image file.

By providing an abnormally large image height value in the file's metadata, an attacker can trick the library into writing attacker-controlled color data to an arbitrary memory location. This memory corruption can be exploited to cause a denial of service (application crash) or to achieve arbitrary code execution with the permissions of the user.(CVE-2025-9900)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.3.0~9.h31.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
