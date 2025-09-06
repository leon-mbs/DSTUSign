using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Numerics;

namespace DSTUSign
{
    public class Point
    {
        public Field x;
        public Field y;

        public Point(Field x,Field y)
        {
            this.x = x;
            this.y = y;

        }
        public Point add(Point p)
        {
            var a = new Field(this.x.curve.a.value, this.x.curve);
            var pz = new Point(Field.get0(this.x.curve), Field.get0(this.x.curve));

            var x0 = this.x.clone();
            var y0 = this.y.clone();
            var x1 = p.x.clone();
            var y1 = p.y.clone();
            if (this.iszero()) {
                return p;
            }

            if (p.iszero()) {
                return this;
            }
            Field x2 = null;
            Field lbd = null;

            if (x0.compare(x1) != 0) {
               var  tmp = y0.add(y1);
               var tmp2 = x0.add(x1);
                 lbd = tmp.mulmod(tmp2.invert());
                   x2 = a.add(lbd.mulmod(lbd));
                x2 = x2.add(lbd);
                x2 = x2.add(x0);
                x2 = x2.add(x1);
            } else
            {
                if (y1.compare(y0) != 0) {
                    return pz;
                }
                if (x1.compare(Field.get0(this.x.curve)) == 0) {
                    return pz;
                }

                    lbd = x1.add(p.y.mulmod(p.x.invert()));
                    x2 = lbd.mulmod(lbd).add(a);
                    x2 = x2.add(lbd);
                }

                var y2 = lbd.mulmod(x1.add(x2));
                y2 = y2.add(x2);
                y2 = y2.add(y1);

                pz.x = x2.clone();
                pz.y = y2.clone();

            return pz;
        }
        public Point  mul(Field f)
        {

             var pz = new Point(Field.get0(f.curve), Field.get0(f.curve));

             var p = this.clone();
         
             for (int j = f.getBitLength() - 1; j >= 0; j--) {
                if (f.testBit(j) == 1) {
                  pz = pz.add(p);
                  p = p.add(p);
                } else
                {
                  p = pz.add(p);
                  pz = pz.add(pz);
                }
            }


            return pz;
           
        }

        public Point negate()
        {
            return new Point(this.x, this.x.add(this.y));
        }

        public Point clone()
        {
            return new Point(this.x, this.y);
        }

        public bool isequal(Point p)
        {
            return ( this.x.compare(p.x) == 0) && ( this.y.compare(p.y) == 0);
        }

        public bool iszero()
        {

            return ( this.x.is0()) && ( this.y.is0());
        }
    }
}
