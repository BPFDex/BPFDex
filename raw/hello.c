#include <stdio.h>

struct hello
{
  int a;
  int b;
};

int hi(char* s, size_t t, unsigned long l, int* n,int n2,struct hello *h,int* qq,int pp) {
  printf("%s\n", s);
  printf("%p\n", s);
  printf("%lu\n", t);
  printf("%lx\n", l);
  printf("%p\n", &l);
  printf("%d\n", *n);  
  printf("%p\n", n);  
  printf("%p\n", qq);  
  printf("%d\n", pp);  
  return 0;
}
int main() {
  char* site = "hasjidchsakfchdkljfhvbllrvbjhaksldbjcfvklberhjkfbvkldsabjvksabvck";
  printf("%d",(int)sizeof(site));
  size_t t = 325469874156;
  unsigned long l = 0xff15be41a1; 
  t=t+0x20;
  int a = 55;
  int* n = &a;
  char* f = "hahaha";
  struct hello h;
  h.a=54;
  h.b=33;
  hi(site, t, l, n,a,&h,n,a+9);
  return 0;
}