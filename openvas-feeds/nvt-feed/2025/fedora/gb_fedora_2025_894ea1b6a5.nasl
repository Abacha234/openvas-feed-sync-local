# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.894101971986975");
  script_tag(name:"creation_date", value:"2025-12-17 10:50:36 +0000 (Wed, 17 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-894ea1b6a5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-894ea1b6a5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-894ea1b6a5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dr_libs' package(s) announced via the FEDORA-2025-894ea1b6a5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## dr_flac

### v0.13.2 - 2025-12-02
 - Improve robustness of the parsing of picture metadata to improve support for memory constrained embedded devices.
 - Fix a warning about an assigned by unused variable.
 - Improvements to drflac_open_and_read_pcm_frames_*() and family to avoid excessively large memory allocations from malformed files.

### v0.13.1 - 2025-09-10
 - Fix an error with the NXDK build.

## dr_mp3

### v0.7.2 - 2025-12-02
 - Reduce stack space to improve robustness on embedded systems.
 - Fix a compilation error with MSVC Clang toolset relating to cpuid.
 - Fix an error with APE tag parsing.

The APE tag parsing defect may have security implications, github.com/mackron/dr_libs/issues/291.

### v0.7.1 - 2025-09-10
 - Silence a warning with GCC.
 - Fix an error with the NXDK build.
 - Fix a decoding inconsistency when seeking. Prior to this change, reading to the end of the stream immediately after initializing will result in a different number of samples read than if the stream is seeked to the start and read to the end.

## dr_wav

### v0.14.2 - 2025-12-02
 - Fix a compilation warning.

### v0.14.1 - 2025-09-10
 - Fix an error with the NXDK build.");

  script_tag(name:"affected", value:"'dr_libs' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"dr_flac-devel", rpm:"dr_flac-devel~0.13.2^20251201.877b096~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs", rpm:"dr_libs~0^20251201.877b096~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs-devel", rpm:"dr_libs-devel~0^20251201.877b096~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_libs-doc", rpm:"dr_libs-doc~0^20251201.877b096~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_mp3-devel", rpm:"dr_mp3-devel~0.7.2^20251201.877b096~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dr_wav-devel", rpm:"dr_wav-devel~0.14.2^20251201.877b096~1.fc43", rls:"FC43"))) {
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
