import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log("Cleaning database for production launch...");
  await prisma.message.deleteMany();
  await prisma.evaluation.deleteMany();
  await prisma.attendance.deleteMany();
  await prisma.payment.deleteMany();
  await prisma.training.deleteMany();
  await prisma.player.deleteMany();
  await prisma.coach.deleteMany();
  await prisma.parent.deleteMany();
  await prisma.group.deleteMany();
  await prisma.user.deleteMany();

  console.log("Seeding admin user...");
  await prisma.user.create({
    data: {
      id: "admin",
      email: "admin@ghadirsports.sa",
      password: bcrypt.hashSync("Ghadir@2026!", 10),
      role: "ADMIN",
      name: "مدير الأكاديمية"
    }
  });

  console.log("Seeding default coach...");
  const coachUser = await prisma.user.create({
    data: {
      id: "u-coach-1",
      email: "coach@ghadirsports.sa",
      password: bcrypt.hashSync("Ghadir@2026!", 10),
      role: "COACH",
      name: "الكابتن أحمد علي"
    }
  });

  const coach = await prisma.coach.create({
    data: {
      id: "c1",
      userId: coachUser.id,
      specialty: "تدريب عام"
    }
  });

  console.log("Seeding sports groups for فرع المصيف...");
  const groupsData = [
    { id: 'g-football-juniors', name: 'كرة القدم صغار (من 5 إلى 10 سنوات)', color: '#16A34A', price8: 250, price12: 350, price16: 450 },
    { id: 'g-football-seniors', name: 'كرة القدم كبار بنين', color: '#15803D', price8: 250, price12: 350, price16: 450 },
    { id: 'g-swimming-men', name: 'سباحة مدربين (رجال)', color: '#0284C7', price8: 300, price12: 400, price16: 500 },
    { id: 'g-swimming-women', name: 'سباحة مدربات (نساء)', color: '#DB2777', price8: 300, price12: 400, price16: 500 },
    { id: 'g-gymnastics', name: 'جمباز', color: '#EA580C', price8: 250, price12: 350, price16: 450 },
    { id: 'g-taekwondo', name: 'تايكوندو', color: '#7C3AED', price8: 250, price12: 350, price16: 450 },
    { id: 'g-basketball-girls', name: 'كرة سلة بنات', color: '#D97706', price8: 250, price12: 350, price16: 450 },
    { id: 'g-basketball-boys', name: 'كرة سلة بنين', color: '#B45309', price8: 250, price12: 350, price16: 450 }
  ];

  for (const g of groupsData) {
    await prisma.group.create({ data: g });
  }

  console.log("Seeding training schedules for فرع المصيف...");
  const trainingsData = [
    { id: 't-football-juniors', groupId: 'g-football-juniors', days: ["الخميس", "الجمعة", "السبت", "الثلاثاء"], time: "", duration: 90, field: "ملعب كرة القدم", title: "تمرين كرة القدم صغار" },
    { id: 't-football-seniors', groupId: 'g-football-seniors', days: ["الخميس", "الجمعة", "السبت", "الثلاثاء"], time: "", duration: 90, field: "ملعب كرة القدم", title: "تمرين كرة القدم كبار بنين" },
    { id: 't-swimming-men', groupId: 'g-swimming-men', days: ["الخميس", "الجمعة", "السبت", "الثلاثاء"], time: "", duration: 60, field: "المسبح", title: "تمرين سباحة مدربين (رجال)" },
    { id: 't-swimming-women', groupId: 'g-swimming-women', days: ["الجمعة", "السبت", "الثلاثاء"], time: "", duration: 60, field: "المسبح", title: "تمرين سباحة مدربات (نساء)" },
    { id: 't-gymnastics', groupId: 'g-gymnastics', days: ["الخميس", "السبت", "الثلاثاء"], time: "", duration: 60, field: "صالة الجمباز", title: "تمرين جمباز" },
    { id: 't-taekwondo', groupId: 'g-taekwondo', days: ["الخميس", "الجمعة", "السبت", "الثلاثاء"], time: "", duration: 60, field: "صالة الدفاع عن النفس", title: "تمرين تايكوندو" },
    { id: 't-basketball-girls', groupId: 'g-basketball-girls', days: ["الخميس", "الجمعة", "السبت", "الثلاثاء"], time: "", duration: 60, field: "ملعب كرة السلة", title: "تمرين كرة سلة بنات" },
    { id: 't-basketball-boys', groupId: 'g-basketball-boys', days: ["الخميس", "الجمعة", "السبت", "الثلاثاء"], time: "", duration: 60, field: "ملعب كرة السلة", title: "تمرين كرة سلة بنين" }
  ];

  for (const tr of trainingsData) {
    await prisma.training.create({
      data: {
        id: tr.id,
        days: tr.days,
        time: tr.time,
        duration: tr.duration,
        field: tr.field,
        title: tr.title,
        isRecurring: true,
        type: 'training',
        groupId: tr.groupId,
        coachId: coach.id
      }
    });
  }

  console.log("Database successfully prepared for فرع المصيف launch!");
}

main()
  .catch((e) => {
    console.error("Error during seed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
