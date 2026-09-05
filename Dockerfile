# R Package Validation Gateway — container image (Phase 4)
#
# CAVEAT: authored and statically reviewed on a workstation WITHOUT Docker;
# build/run verification is deferred to a Docker-enabled host or CI runner
# (see docs/container_verification.md for the exact checklist).
#
# Base: rocker/r-ver:4.5.3 — R 4.5.3 on Ubuntu 24.04 (noble); matches the
# r-platform image's R version (see docs/platform_integration.md).
# Originally authored for 4.6.0, but the pinned CRAN snapshot (2026-04-15)
# predates R 4.6: its Rcpp 1.1.1 fails to compile against R 4.6 headers
# ('R_NamespaceRegistry was not declared', verified the Docker build host 2026-09-02),
# which kills riskmetric's whole dependency chain. R 4.5.x is the snapshot's
# contemporary R line AND has PPM noble binaries for near-instant installs.
# The gateway itself is Python; Rscript is only used to invoke riskmetric.
# Noble's apt python3 is 3.12 — the gateway is stdlib-only and requires
# Python >= 3.11 (README).
FROM rocker/r-ver:4.5.3

# CRAN snapshot pin: Posit Package Manager snapshot 2026-04-15 (after the
# riskmetric 0.2.7 release of 2026-04-01; verified 2026-09-02 that this
# snapshot serves riskmetric 0.2.7). This date is THE snapshot reference for
# the container build.
# __linux__/noble path serves PPM BINARY packages — source installs of
# riskmetric deps (xml2/curl/urltools) fail on rocker/r-ver because the
# image ships no libxml2/libcurl -dev headers (verified on the Docker build host
# 2026-09-02: 38 compile warnings, install aborted). Binary packages need
# no toolchain. Pinned snapshot date is unchanged.
ARG CRAN_SNAPSHOT="https://packagemanager.posit.co/cran/__linux__/noble/2026-04-15"

# python3 (gateway runtime), TeX for the PDF report path (pdflatex;
# texlive-latex-base + recommended covers article/geometry/booktabs/
# longtable/fancyhdr/xcolor used by gateway/templates/report.tex).
# PDF opt-out: drop the two texlive packages to slim the image — report.py
# degrades gracefully to HTML-only with a footer note.
# The three -dev libraries are the toolchain for riskmetric's compiled deps
# (xml2/curl/urltools): PPM serves Linux binaries via the __linux__/noble
# repo path, but R falls back to source when the binary index is not
# picked up — source then needs these headers (verified the Docker build host
# 2026-09-02).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 \
      libxml2-dev \
      libcurl4-openssl-dev \
      libssl-dev \
      texlive-latex-base \
      texlive-latex-recommended \
 && rm -rf /var/lib/apt/lists/*

# riskmetric 0.2.7 from the pinned snapshot; fail the build if the resolved
# version is not exactly 0.2.7 (snapshot drift guard). ARG values are visible
# to RUN as environment variables, so the R expression reads CRAN_SNAPSHOT.
# HTTPUserAgent is set explicitly because --vanilla skips rocker's .Rprofile
# (which normally carries it): without the "R/x.y.z R (x.y.z platform arch
# os)" UA pattern, PPM serves SOURCE packages even on the __linux__/noble
# path, and the source build fails in this image (verified the Docker build host
# 2026-09-02: with the UA the install succeeds via noble binaries).
RUN Rscript --vanilla -e \
      'options(repos = c(CRAN = Sys.getenv("CRAN_SNAPSHOT")), \
               HTTPUserAgent = sprintf("R/%s R (%s)", getRversion(), \
                 paste(getRversion(), R.version$platform, R.version$arch, R.version$os))); \
       install.packages("riskmetric"); \
       v <- as.character(packageVersion("riskmetric")); \
       if (v != "0.2.7") stop("riskmetric version drift: got ", v)'

WORKDIR /app
COPY gateway/ /app/gateway/
COPY config/ /app/config/
COPY run.py /app/
# batch inventory assessment CLI (dashboard.py imports its staleness helpers)
COPY run_inventory.py /app/
COPY README.md /app/
# tests + vendored redline scan are included so the image can self-verify
# (unit tests + --offline regression run in-container without network/R extra)
COPY tests/ /app/tests/
COPY tools/ /app/tools/

# runtime configuration (all overridable at run time)
ENV RSCRIPT=/usr/local/bin/Rscript \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8010
# GATEWAY_HOST=0.0.0.0 is REQUIRED in-container so compose can map the port
# back to localhost on the host; the application default (127.0.0.1) still
# applies outside containers. GITHUB_TOKEN is passed through at run time,
# never baked into the image.
# Port 8010 follows the platform's internal Python-service port block
# (8007=safety, 8008=rag, 8009=studio); the platform compose sets
# GATEWAY_PORT=8010 explicitly — this default just keeps the image
# self-consistent when run standalone.

# non-root runtime user; data/ is a volume mount point (audit persistence)
RUN useradd --create-home --uid 10001 gateway \
 && mkdir -p /app/data \
 && chown -R gateway:gateway /app
USER gateway

EXPOSE 8010

HEALTHCHECK --interval=60s --timeout=15s --start-period=30s --retries=3 \
  CMD python3 -c "import os,urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen( \
 f\"http://127.0.0.1:{os.environ.get('GATEWAY_PORT','8010')}/health\", \
 timeout=10).status == 200 else 1)"

# note: ARG CRAN_SNAPSHOT must stay declared ABOVE the install RUN that reads
# it via Sys.getenv (ARGs are in RUN's environment; redeclare after FROM if
# reordered).
CMD ["python3", "-m", "gateway.server"]
