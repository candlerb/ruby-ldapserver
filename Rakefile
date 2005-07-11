task :default => [:src]

VER="0.3"

task :rdoc do
  sh "rdoc -x '~$' -m README README lib"
end

srcball = "ruby-ldapserver-#{VER}.tgz"
sourcefiles = ["README","COPYING","ChangeLog","examples/README","test/core.schema"] + Dir["**/*.rb"]

task :src do
  tmpdir = "ruby-ldapserver-#{VER}"
  rm tmpdir if File.exist?(tmpdir)
  File.symlink(".", tmpdir)
  
  srcs = sourcefiles.collect { |f| tmpdir+"/"+f }
  rm(srcball) if File.exist?(srcball)
  sh "tar", "-czf", srcball, *srcs
  rm tmpdir
end

task :tag do
  sh "cvs update"
  sh "cvs commit"
  sh "cvs tag RELEASE_#{VER.gsub(/\./,'_')}"
end
  