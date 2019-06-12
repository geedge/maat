#include "igraph/igraph.h"
#include <assert.h>

void print_vector(igraph_vector_t *v, FILE *f) {
  long int i;
  for (i=0; i<igraph_vector_size(v); i++) {
    fprintf(f, " %li", (long int) VECTOR(*v)[i]);
  }
  fprintf(f, "\n");
}

int main() {

	igraph_t g;
	int ret;
	ret=igraph_empty(&g, 0, IGRAPH_DIRECTED);

	igraph_es_t es;
	igraph_integer_t edge_num_before=0, edge_num_after=0;
	int v[10];
	int i=0;
	for(i=0; i<sizeof(v)/sizeof(int); i++)
	{
		v[i]=i;
		igraph_add_vertices(&g, 1, NULL);	//Add 1 vertice.
	}
	igraph_add_edge(&g, v[0], v[1]);
	igraph_add_edge(&g, v[0], v[1]);

	igraph_add_edge(&g, v[2], v[3]);

	int edge_id=0;
	ret=igraph_get_eid(&g, &edge_id, v[2], v[3], IGRAPH_DIRECTED, 0);
	assert(edge_id>0);

	ret=igraph_es_pairs_small(&es, IGRAPH_DIRECTED, v[0], v[1], -1);
	assert(ret==IGRAPH_SUCCESS);
	edge_num_before=igraph_ecount(&g);
	ret=igraph_delete_edges(&g, es);
	edge_num_after=igraph_ecount(&g);
	assert(edge_num_before-edge_num_after==1);
	assert(ret==IGRAPH_SUCCESS);
	igraph_es_destroy(&es);

	ret=igraph_es_pairs_small(&es, IGRAPH_DIRECTED, v[3], v[4], -1);
	assert(ret==IGRAPH_SUCCESS);
	edge_num_before=igraph_ecount(&g);
	/* error test, no such edge to delete */
	igraph_set_error_handler(igraph_error_handler_ignore);

	ret=igraph_delete_edges(&g, es);
	edge_num_after=igraph_ecount(&g);
	assert(edge_num_before=edge_num_after);
	assert(ret!=IGRAPH_SUCCESS);
	igraph_es_destroy(&es);


	igraph_destroy(&g);

  return 0;
}

