#
# The contents of this file are subject to the license and copyright
# detailed in the LICENSE and NOTICE files at the root of the source
# tree and available online at
#
# http://www.dspace.org/license/
#

# To build use root as context for (easier) access to solr cfgs
# docker build --build-arg SOLR_VERSION=8.11 -f ./dspace/src/main/docker/dspace-solr/Dockerfile .
# This will be published as dspace/dspace-solr:$DSPACE_VERSION

ARG SOLR_VERSION=8.11

FROM docker.io/solr:${SOLR_VERSION}

ENV CONFIGSET_PATH=/opt/solr/server/solr/configsets
    
USER root

# NOTE: "solrconfigs" MUST be passed in by docker-compose via "additional_contexts"
# OR via "docker build --build-context solrconfigs=[path-to-dspace/solr]"
COPY --from=solrconfigs authority $CONFIGSET_PATH/authority
COPY --from=solrconfigs oai $CONFIGSET_PATH/oai
COPY --from=solrconfigs search $CONFIGSET_PATH/search
COPY --from=solrconfigs statistics $CONFIGSET_PATH/statistics
COPY --from=solrconfigs qaevent $CONFIGSET_PATH/qaevent
COPY --from=solrconfigs suggestion $CONFIGSET_PATH/suggestion

COPY docker-entrypoint.sh /usr/local/bin/gub-docker-entrypoint.sh
ENTRYPOINT ["gub-docker-entrypoint.sh"]

RUN chown -R solr:solr /opt/solr/server/solr/configsets

USER solr
