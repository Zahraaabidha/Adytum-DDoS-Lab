# Isolation-test fixture image. curl/bind-tools/iputils are baked in at BUILD
# time (build has normal internet access), so the resulting container needs
# NO egress at all once it's attached only to internal:true networks --
# which is exactly the property this test is proving.
FROM alpine:3.20
RUN apk add --no-cache curl bind-tools iputils
CMD ["sleep", "infinity"]
