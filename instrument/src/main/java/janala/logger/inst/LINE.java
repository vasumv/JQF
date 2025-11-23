package janala.logger.inst;

public class LINE extends Instruction {
    public LINE(int iid, int mid) {
        super(iid, mid);
    }

    @Override
    public void visit(IVisitor visitor) {
        visitor.visitLINE(this);
    }

    @Override
    public String toString() {
        return "LINE iid=" + iid + " line=" + mid;
    }
}
