#!/bin/bash

set -e
set -x

if [[ "$#" -eq 0 || "${1:0:1}" == '-' ]]; then
    echo "Creating cores"

    init-var-solr

    # List of DSpace cores
    CORES=("authority" "oai" "search" "statistics" "qaevent" "suggestion")

    # Precreate cores if they do not exist
    for CORE in "${CORES[@]}"; do
        echo "Precreating core: $CORE"
        precreate-core "$CORE" "/opt/solr/server/solr/configsets/$CORE"
    done

    # Start Solr in foreground
    exec solr-fg "$@"
else
    # If arguments were provided, run them directly
    exec "$@"
fi

