# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.99889989997077");
  script_cve_id("CVE-2024-50614");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-9b8c8ca077)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9b8c8ca077");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9b8c8ca077");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322189");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350891");
  script_xref(name:"URL", value:"https://github.com/leethomason/tinyxml2/compare/10.0.0...11.0.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Macaulay2, ags, bullet, cppcheck, docparser, dvblinkremote, fuse-encfs, gazebo, lgogdownloader, libmediainfo, linbox, linux-sgx, musescore, openmw, rarian, tinyxml2, urdfdom, vdr-epg2vdr, vdr-osd2web, xrootd-s3-http' package(s) announced via the FEDORA-2025-9b8c8ca077 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security update for CVE-2024-50614: updates `tinyxml2` to [11.0.0]([link moved to references]).");

  script_tag(name:"affected", value:"'Macaulay2, ags, bullet, cppcheck, docparser, dvblinkremote, fuse-encfs, gazebo, lgogdownloader, libmediainfo, linbox, linux-sgx, musescore, openmw, rarian, tinyxml2, urdfdom, vdr-epg2vdr, vdr-osd2web, xrootd-s3-http' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"Macaulay2", rpm:"Macaulay2~1.25.06~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Macaulay2-debuginfo", rpm:"Macaulay2-debuginfo~1.25.06~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Macaulay2-debugsource", rpm:"Macaulay2-debugsource~1.25.06~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ags", rpm:"ags~3.6.2.12~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ags-debuginfo", rpm:"ags-debuginfo~3.6.2.12~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ags-debugsource", rpm:"ags-debugsource~3.6.2.12~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet", rpm:"bullet~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet-debuginfo", rpm:"bullet-debuginfo~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet-debugsource", rpm:"bullet-debugsource~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet-devel", rpm:"bullet-devel~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet-devel-doc", rpm:"bullet-devel-doc~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet-extras", rpm:"bullet-extras~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet-extras-debuginfo", rpm:"bullet-extras-debuginfo~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bullet-extras-devel", rpm:"bullet-extras-devel~3.08~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck", rpm:"cppcheck~2.18.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck-debuginfo", rpm:"cppcheck-debuginfo~2.18.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck-debugsource", rpm:"cppcheck-debugsource~2.18.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck-gui", rpm:"cppcheck-gui~2.18.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck-gui-debuginfo", rpm:"cppcheck-gui-debuginfo~2.18.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cppcheck-htmlreport", rpm:"cppcheck-htmlreport~2.18.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docparser", rpm:"docparser~1.0.16~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docparser-debuginfo", rpm:"docparser-debuginfo~1.0.16~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docparser-debugsource", rpm:"docparser-debugsource~1.0.16~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docparser-devel", rpm:"docparser-devel~1.0.16~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvblinkremote", rpm:"dvblinkremote~0.2.0~0.37.beta.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvblinkremote-debuginfo", rpm:"dvblinkremote-debuginfo~0.2.0~0.37.beta.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvblinkremote-debugsource", rpm:"dvblinkremote-debugsource~0.2.0~0.37.beta.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvblinkremote-devel", rpm:"dvblinkremote-devel~0.2.0~0.37.beta.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvblinkremote-libs", rpm:"dvblinkremote-libs~0.2.0~0.37.beta.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvblinkremote-libs-debuginfo", rpm:"dvblinkremote-libs-debuginfo~0.2.0~0.37.beta.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-encfs", rpm:"fuse-encfs~1.9.5~26.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-encfs-debuginfo", rpm:"fuse-encfs-debuginfo~1.9.5~26.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-encfs-debugsource", rpm:"fuse-encfs-debugsource~1.9.5~26.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo", rpm:"gazebo~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-common", rpm:"gazebo-common~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-debuginfo", rpm:"gazebo-debuginfo~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-debugsource", rpm:"gazebo-debugsource~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-devel", rpm:"gazebo-devel~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-doc", rpm:"gazebo-doc~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-libs", rpm:"gazebo-libs~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-libs-debuginfo", rpm:"gazebo-libs-debuginfo~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-media", rpm:"gazebo-media~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-ode", rpm:"gazebo-ode~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-ode-debuginfo", rpm:"gazebo-ode-debuginfo~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gazebo-ode-devel", rpm:"gazebo-ode-devel~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gootville-fonts", rpm:"gootville-fonts~1.3~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gootville-text-fonts", rpm:"gootville-text-fonts~1.2~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lgogdownloader", rpm:"lgogdownloader~3.16~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lgogdownloader-debuginfo", rpm:"lgogdownloader-debuginfo~3.16~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lgogdownloader-debugsource", rpm:"lgogdownloader-debugsource~3.16~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmediainfo", rpm:"libmediainfo~25.04~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmediainfo-debuginfo", rpm:"libmediainfo-debuginfo~25.04~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmediainfo-debugsource", rpm:"libmediainfo-debugsource~25.04~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmediainfo-devel", rpm:"libmediainfo-devel~25.04~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linbox", rpm:"linbox~1.7.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linbox-debuginfo", rpm:"linbox-debuginfo~1.7.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linbox-debugsource", rpm:"linbox-debugsource~1.7.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linbox-devel", rpm:"linbox-devel~1.7.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-sgx", rpm:"linux-sgx~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-sgx-debuginfo", rpm:"linux-sgx-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-sgx-debugsource", rpm:"linux-sgx-debugsource~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mscore-fonts", rpm:"mscore-fonts~2.002~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mscorebc-fonts", rpm:"mscorebc-fonts~1.0~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mscoretabulature-fonts", rpm:"mscoretabulature-fonts~001.000~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mscoretext-fonts", rpm:"mscoretext-fonts~1.0~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musejazz-fonts", rpm:"musejazz-fonts~1.0~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musejazz-text-fonts", rpm:"musejazz-text-fonts~1.0~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musescore", rpm:"musescore~4.3.2~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musescore-data", rpm:"musescore-data~4.3.2~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musescore-debuginfo", rpm:"musescore-debuginfo~4.3.2~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musescore-debugsource", rpm:"musescore-debugsource~4.3.2~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musescore-soundfont", rpm:"musescore-soundfont~0.2.0~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"musescoreicon-fonts", rpm:"musescoreicon-fonts~1.0~21.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmw", rpm:"openmw~0.49.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmw-cs", rpm:"openmw-cs~0.49.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmw-cs-debuginfo", rpm:"openmw-cs-debuginfo~0.49.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmw-debuginfo", rpm:"openmw-debuginfo~0.49.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmw-debugsource", rpm:"openmw-debugsource~0.49.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmw-tools", rpm:"openmw-tools~0.49.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmw-tools-debuginfo", rpm:"openmw-tools-debuginfo~0.49.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"player-gazebo", rpm:"player-gazebo~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"player-gazebo-debuginfo", rpm:"player-gazebo-debuginfo~10.2.0~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rarian", rpm:"rarian~0.8.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rarian-compat", rpm:"rarian-compat~0.8.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rarian-compat-debuginfo", rpm:"rarian-compat-debuginfo~0.8.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rarian-debuginfo", rpm:"rarian-debuginfo~0.8.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rarian-debugsource", rpm:"rarian-debugsource~0.8.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rarian-devel", rpm:"rarian-devel~0.8.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-aesm", rpm:"sgx-aesm~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-aesm-debuginfo", rpm:"sgx-aesm-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-common", rpm:"sgx-common~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-devel", rpm:"sgx-devel~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-devel", rpm:"sgx-enclave-devel~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-devel-debuginfo", rpm:"sgx-enclave-devel-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-ide-unsigned", rpm:"sgx-enclave-latest-ide-unsigned~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-pce-unsigned", rpm:"sgx-enclave-latest-pce-unsigned~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-qe3-unsigned", rpm:"sgx-enclave-latest-qe3-unsigned~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-tdqe-unsigned", rpm:"sgx-enclave-latest-tdqe-unsigned~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-libs", rpm:"sgx-libs~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-libs-debuginfo", rpm:"sgx-libs-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-mpa", rpm:"sgx-mpa~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-mpa-debuginfo", rpm:"sgx-mpa-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pccs", rpm:"sgx-pccs~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pccs-admin", rpm:"sgx-pccs-admin~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pccs-debuginfo", rpm:"sgx-pccs-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pckid-tool", rpm:"sgx-pckid-tool~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pckid-tool-debuginfo", rpm:"sgx-pckid-tool-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-attest-devel", rpm:"tdx-attest-devel~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-attest-libs", rpm:"tdx-attest-libs~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-attest-libs-debuginfo", rpm:"tdx-attest-libs-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-qgs", rpm:"tdx-qgs~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-qgs-debuginfo", rpm:"tdx-qgs-debuginfo~2.26~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml2", rpm:"tinyxml2~11.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml2-debuginfo", rpm:"tinyxml2-debuginfo~11.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml2-debugsource", rpm:"tinyxml2-debugsource~11.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml2-devel", rpm:"tinyxml2-devel~11.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"urdfdom", rpm:"urdfdom~4.0.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"urdfdom-debuginfo", rpm:"urdfdom-debuginfo~4.0.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"urdfdom-debugsource", rpm:"urdfdom-debugsource~4.0.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"urdfdom-devel", rpm:"urdfdom-devel~4.0.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-epg2vdr", rpm:"vdr-epg2vdr~1.2.17~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-epg2vdr-debuginfo", rpm:"vdr-epg2vdr-debuginfo~1.2.17~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-epg2vdr-debugsource", rpm:"vdr-epg2vdr-debugsource~1.2.17~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-osd2web", rpm:"vdr-osd2web~0.3.2~19.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-osd2web-debuginfo", rpm:"vdr-osd2web-debuginfo~0.3.2~19.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-osd2web-debugsource", rpm:"vdr-osd2web-debugsource~0.3.2~19.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrootd-s3-http", rpm:"xrootd-s3-http~0.4.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrootd-s3-http-debuginfo", rpm:"xrootd-s3-http-debuginfo~0.4.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrootd-s3-http-debugsource", rpm:"xrootd-s3-http-debugsource~0.4.1~4.fc43", rls:"FC43"))) {
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
