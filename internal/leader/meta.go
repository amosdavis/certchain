package leader

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func metaObject(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: namespace, Name: name}
}
