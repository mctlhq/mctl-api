package deployplan

import (
	"errors"
	"fmt"
	"reflect"
)

// ErrChartDefaultsUnusable is ChangesRender's answer when the chart's own
// values.yaml cannot serve as the defaults layer: unparseable, not a
// mapping, or empty. It is never read as "no defaults".
var ErrChartDefaultsUnusable = errors.New("chart default values are unusable")

// ChangesRender says whether the intent changes what the chart renders:
// before and after (from CompilePreview) are each layered over the chart's
// default values the way Helm coalesces a values file onto a chart, and the
// results are compared. A key the intent writes with the value the chart
// already defaults to (replicaCount: 1, service.port: 8080) is therefore
// not a change; any other difference is (mctl-api#1058).
//
// It fails closed: defaults that cannot be used are an error, never an
// empty layer, because an empty layer would turn "could not read the
// chart" into a verdict.
func ChangesRender(chartDefaults []byte, before, after map[string]any) (bool, error) {
	if len(chartDefaults) == 0 {
		return false, fmt.Errorf("%w: empty", ErrChartDefaultsUnusable)
	}
	defaults, err := parseValues(chartDefaults)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrChartDefaultsUnusable, err)
	}
	if len(defaults) == 0 {
		return false, fmt.Errorf("%w: no values", ErrChartDefaultsUnusable)
	}
	b := coalesce(deepCopy(before).(map[string]any), defaults)
	a := coalesce(deepCopy(after).(map[string]any), defaults)
	return !reflect.DeepEqual(b, a), nil
}

// coalesce layers defaults under values, as Helm coalesces a values file
// over a chart: values win, nested mappings merge, and a list or scalar
// replaces the default whole. Helm also lets a null in values delete a
// default key; that is not reproduced, because the intent never writes a
// null and a key it does not write is the same on both sides of the
// comparison. values is modified and returned.
func coalesce(values, defaults map[string]any) map[string]any {
	for k, dv := range defaults {
		v, set := values[k]
		if !set {
			values[k] = deepCopy(dv)
			continue
		}
		vm, vok := v.(map[string]any)
		dm, dok := dv.(map[string]any)
		if vok && dok {
			values[k] = coalesce(vm, dm)
		}
	}
	return values
}
